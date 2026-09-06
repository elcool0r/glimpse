// Package filesystem collects mounted, non-pseudo filesystem capacity data.
package filesystem

import (
	"context"
	"io"
	"os"
	"path/filepath"
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

var pseudoTypes = map[string]struct{}{
	"autofs": {}, "bpf": {}, "cgroup": {}, "cgroup2": {}, "configfs": {}, "debugfs": {},
	"devpts": {}, "devtmpfs": {}, "efivarfs": {}, "fusectl": {}, "hugetlbfs": {},
	"mqueue": {}, "nsfs": {}, "overlay": {}, "proc": {}, "pstore": {}, "ramfs": {},
	"securityfs": {}, "sysfs": {}, "tmpfs": {}, "tracefs": {},
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
	"jfs": {}, "nilfs2": {}, "reiserfs": {}, "xfs": {}, "zfs": {},
}

// Collect reads /proc/self/mountinfo and statfs data. Missing procfs is reported
// to callers as an error; permission failures on individual mounts are skipped.
func Collect(ctx context.Context, procRoot string) ([]Usage, error) {
	return collectWithStatfs(ctx, procRoot, syscall.Statfs)
}

func collectWithStatfs(ctx context.Context, procRoot string, statfs func(string, *syscall.Statfs_t) error) ([]Usage, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	f, err := os.Open(filepath.Join(procRoot, "self/mountinfo"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	mounts, err := ParseMountInfo(f)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	result := make([]Usage, 0, len(mounts))
	for _, mount := range mounts {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !IsReal(mount) {
			continue
		}
		if _, ok := localTypes[mount.Type]; !ok && mount.Type != "overlay" {
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
	return result, nil
}
