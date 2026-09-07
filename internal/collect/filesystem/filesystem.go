// Package filesystem collects mounted, non-pseudo filesystem capacity data.
package filesystem

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/elcool0r/glimpse/internal/collect/mountinfo"
)

// Mount is one entry from the shared mountinfo parser.
type Mount = mountinfo.Entry

// Usage uses bytes for capacity values and fractions (0..1) for utilization.
type Usage struct {
	Mount
	TotalBytes        uint64
	FreeBytes         uint64
	AvailableBytes    uint64
	UsedBytes         uint64
	UsedFraction      float64
	Inodes            uint64
	FreeInodes        uint64
	UsedInodes        uint64
	UsedInodeFraction float64
}

// Exclusion records a real mount deliberately omitted from statfs. These
// mounts are not failures: probing network and FUSE filesystems can itself
// block during the incident glimpse is meant to diagnose. Keeping the fact
// separate makes that bounded behavior visible to JSON and verbose output.
type Exclusion struct {
	Type  string
	Count int
}

// tmpfs is deliberately not in this set: it is RAM-backed but genuinely
// mountable with a fixed size, and can fill up exactly like a disk-backed
// filesystem (a provisioned scratch/cache volume, a container's shared
// memory segment under real load). Excluding it entirely hid a real "disk"
// full condition. The usual small system tmpfs mounts (/run, /dev/shm,
// per-session XDG runtime dirs) rarely approach the existing conservative
// capacity thresholds, so this does not trade away the "avoid false
// positives" rule -- it only stops hiding a genuine one.
var pseudoTypes = map[string]struct{}{
	"autofs": {}, "bpf": {}, "cgroup": {}, "cgroup2": {}, "configfs": {}, "debugfs": {},
	"devpts": {}, "devtmpfs": {}, "efivarfs": {}, "fusectl": {}, "hugetlbfs": {},
	"mqueue": {}, "nsfs": {}, "overlay": {}, "proc": {}, "pstore": {}, "ramfs": {},
	"securityfs": {}, "sysfs": {}, "tracefs": {},
}

// ParseMountInfo reads mount records. It delegates to the shared parser so
// mount state has one implementation rather than one per consumer.
func ParseMountInfo(r io.Reader) ([]Mount, error) { return mountinfo.Parse(r) }

func IsReal(m Mount) bool {
	if m.Type == "overlay" {
		return m.Target == "/"
	}
	if _, pseudo := pseudoTypes[m.Type]; pseudo {
		return false
	}
	return m.Target != "" && !strings.HasPrefix(m.Target, "/proc/") && !strings.HasPrefix(m.Target, "/sys/")
}

// Statfs can block on network and FUSE filesystems, so only known local types
// are queried during a bounded health snapshot.
var localTypes = map[string]struct{}{
	"btrfs": {}, "ext2": {}, "ext3": {}, "ext4": {}, "f2fs": {},
	"vfat": {}, "exfat": {}, "ntfs3": {}, "erofs": {}, "squashfs": {}, "iso9660": {}, "udf": {},
	"jfs": {}, "nilfs2": {}, "reiserfs": {}, "xfs": {}, "zfs": {}, "tmpfs": {},
}

// Collect reads /proc/self/mountinfo and statfs data. Missing procfs is reported
// to callers as an error; permission failures on individual mounts are skipped.
func Collect(ctx context.Context, procRoot string) ([]Usage, error) {
	usages, _, err := CollectWithExclusions(ctx, procRoot)
	return usages, err
}

// CollectWithExclusions returns sampled filesystems and the real mount types
// intentionally not probed because they are not known-local filesystems.
func CollectWithExclusions(ctx context.Context, procRoot string) ([]Usage, []Exclusion, error) {
	return collectWithStatfsWithExclusions(ctx, procRoot, syscall.Statfs)
}

func collectWithStatfs(ctx context.Context, procRoot string, statfs func(string, *syscall.Statfs_t) error) ([]Usage, error) {
	usages, _, err := collectWithStatfsWithExclusions(ctx, procRoot, statfs)
	return usages, err
}

func collectWithStatfsWithExclusions(ctx context.Context, procRoot string, statfs func(string, *syscall.Statfs_t) error) ([]Usage, []Exclusion, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	f, err := os.Open(filepath.Join(procRoot, "self/mountinfo"))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	mounts, err := ParseMountInfo(f)
	if err != nil {
		return nil, nil, err
	}
	seen := make(map[string]struct{})
	result := make([]Usage, 0, len(mounts))
	excludedTypes := make(map[string]int)
	for _, mount := range mounts {
		if err := ctx.Err(); err != nil {
			return result, exclusions(excludedTypes), err
		}
		if !IsReal(mount) {
			continue
		}
		if _, ok := localTypes[mount.Type]; !ok && mount.Type != "overlay" {
			excludedTypes[mount.Type]++
			continue
		}
		if _, ok := seen[mount.Target]; ok {
			continue
		}
		seen[mount.Target] = struct{}{}
		var st syscall.Statfs_t
		if err := statfs(mount.Target, &st); err != nil {
			continue
		}
		blockSize := uint64(st.Bsize)
		total := uint64(st.Blocks) * blockSize
		free := uint64(st.Bfree) * blockSize
		available := uint64(st.Bavail) * blockSize
		used := total - free
		u := Usage{Mount: mount, TotalBytes: total, FreeBytes: free, AvailableBytes: available, UsedBytes: used, Inodes: uint64(st.Files), FreeInodes: uint64(st.Ffree)}
		// Utilization is measured against space a normal process can actually
		// use, which is what df reports and what an operator will compare this
		// against. Dividing by total capacity instead counts the root reserve
		// as free and reads several points more optimistic than df — on a
		// default ext4 the fraction would still be below 1 at the moment
		// unprivileged writes start failing.
		if usable := used + available; usable > 0 {
			u.UsedFraction = float64(used) / float64(usable)
		}
		if u.Inodes > 0 {
			u.UsedInodes, u.UsedInodeFraction = u.Inodes-u.FreeInodes, float64(u.Inodes-u.FreeInodes)/float64(u.Inodes)
		}
		result = append(result, u)
	}
	// Individual mounts can be temporarily unavailable or statfs can block on
	// remote filesystems. They are intentionally absent rather than presented
	// as a failed host-health check; successfully sampled local mounts remain
	// useful and analyzable.
	return result, exclusions(excludedTypes), nil
}

func exclusions(types map[string]int) []Exclusion {
	if len(types) == 0 {
		return nil
	}
	names := make([]string, 0, len(types))
	for name := range types {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]Exclusion, 0, len(names))
	for _, name := range names {
		result = append(result, Exclusion{Type: name, Count: types[name]})
	}
	return result
}

// ExclusionDiagnostic summarizes intentional exclusions without exposing
// mount sources. It is used only as collection coverage metadata.
func ExclusionDiagnostic(excluded []Exclusion) string {
	if len(excluded) == 0 {
		return ""
	}
	types := make([]string, 0, len(excluded))
	count := 0
	for _, item := range excluded {
		count += item.Count
		types = append(types, fmt.Sprintf("%s=%d", item.Type, item.Count))
	}
	return fmt.Sprintf("filesystem coverage reduced: skipped %d potentially blocking mount(s) (%s)", count, strings.Join(types, ", "))
}
