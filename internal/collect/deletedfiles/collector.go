// Package deletedfiles finds file descriptors still open on deleted
// (unlinked) files -- the classic "df says the disk is full but nothing on
// it looks large" symptom. A process that keeps writing to a file after it
// has been unlinked (a rotated log an old process handle still points at, a
// crashed cleanup job, a long-running download to a file that got removed
// mid-transfer) keeps that data occupying real disk space until every
// process holding the descriptor closes it or exits; nothing in a normal
// directory listing shows it.
//
// Space is accounted once per unique underlying inode, identified by
// (device, inode) -- never by path, PID, fd number, or size, any of which
// can coincide across genuinely distinct files (two different deleted
// journal segments happen to be the same size) or fail to coincide across
// genuinely duplicate references to one file (the same deleted journal held
// open on three separate file descriptors by one process is one 128 MiB
// file, not 384 MiB). Every matching fd still contributes holder
// information for troubleshooting; only the first time an inode is seen
// does it contribute to the space total.
//
// This is a bounded, best-effort scan of /proc/*/fd: it only sees processes
// this user has permission to inspect (the kernel restricts listing another
// user's fd directory), so a non-root run reports fewer processes than a
// root one, not a wrong number of them. That gap is reported as a coverage
// fact (processes scanned vs. skipped), never presented as a completed
// exhaustive sweep. It reads no network and needs no external command, so it
// is always part of the default profile.
package deletedfiles

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

const (
	defaultProcRoot = "/proc"
	// minReportBytes ignores small deleted-but-open files (a log rotated a
	// moment before the writer noticed, a temp file mid-cleanup): common,
	// harmless, and not what this check exists to catch. They are still
	// counted toward the total, just not listed individually.
	minReportBytes = 1 << 20 // 1 MiB
	// maxFiles keeps the report to the largest unique offenders rather than
	// every match, which can otherwise run into the hundreds on a busy host.
	maxFiles = 10
	// maxProcesses bounds the scan on a host running many thousands of
	// processes; this is a health snapshot, not an exhaustive audit.
	maxProcesses = 4096
	// tmpfsMagic is TMPFS_MAGIC from linux/magic.h. shmem-backed anonymous
	// memory -- notably memfd_create() objects, which the .NET runtime uses
	// for JIT code under names like "/memfd:doublemapper" -- lives on this
	// same pseudo-filesystem and shows up identically to a deleted regular
	// file, "(deleted)" suffix included, even though it was never backed by
	// disk at all. Its reported size is virtual/logical (the memfd's max
	// extent), not resident memory or disk usage, so counting it here would
	// both overcount and point at the wrong remediation (this is RAM
	// accounting, not reclaimable disk space). Anything on this filesystem
	// is excluded regardless of name.
	tmpfsMagic = 0x01021994
)

type Collector struct {
	procRoot string
	statfs   func(string, *syscall.Statfs_t) error
}

func New() *Collector { return &Collector{procRoot: defaultProcRoot, statfs: syscall.Statfs} }

func (c *Collector) Name() string { return "deleted-files" }

// Static marks this as a gauge: one bounded scan, not a sampled counter
// needing two boundaries.
func (c *Collector) Static() {}

// inodeKey identifies one underlying file independently of path, PID, fd
// number, or size -- the only identity that cannot be fooled by two
// distinct deleted files sharing a name/size, or by many fds referencing
// one deleted file.
type inodeKey struct {
	dev uint64
	ino uint64
}

func (c *Collector) Collect(ctx context.Context) (collect.Data, error) {
	root := c.procRoot
	if root == "" {
		root = defaultProcRoot
	}
	statfs := c.statfs
	if statfs == nil {
		statfs = syscall.Statfs
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "proc: " + err.Error()}}}, nil
	}
	processesEligible := countEligibleProcesses(entries)

	files := make(map[inodeKey]*model.DeletedFile)
	holderSlot := make(map[inodeKey]map[int]int) // inodeKey -> pid -> index into that file's Holders
	var order []inodeKey                         // first-seen order, for deterministic output before the final sort

	var total uint64
	scanned, skipped, references := 0, 0, 0
	holdingPIDs := make(map[int]struct{})

	for _, entry := range entries {
		if ctx.Err() != nil {
			return collect.Data{}, ctx.Err()
		}
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory (self, thread-self, net, ...)
		}
		if scanned+skipped >= maxProcesses {
			break
		}
		fdDir := filepath.Join(root, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// Permission denied for another user's process, or the process
			// exited between the two reads -- both routine, not a fault.
			skipped++
			continue
		}
		scanned++
		comm := readComm(root, entry.Name())
		for _, fd := range fds {
			fdPath := filepath.Join(fdDir, fd.Name())
			target, err := os.Readlink(fdPath)
			if err != nil || !strings.HasPrefix(target, "/") || !strings.HasSuffix(target, " (deleted)") {
				// Sockets/pipes/anon_inode fds never have this form, and a
				// live (non-deleted) path is not what this check looks for.
				continue
			}
			info, err := os.Stat(fdPath)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if onTmpfs(statfs, fdPath) {
				continue
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			key := inodeKey{dev: uint64(stat.Dev), ino: stat.Ino}
			references++
			holdingPIDs[pid] = struct{}{}

			file, seen := files[key]
			if !seen {
				bytes := allocatedBytes(stat)
				file = &model.DeletedFile{
					Device: formatDevice(uint64(stat.Dev)),
					Inode:  stat.Ino,
					Path:   strings.TrimSuffix(target, " (deleted)"),
					Bytes:  bytes,
				}
				files[key] = file
				holderSlot[key] = make(map[int]int)
				order = append(order, key)
				total += bytes
			}
			if slot, ok := holderSlot[key][pid]; ok {
				file.Holders[slot].FDs = append(file.Holders[slot].FDs, fd.Name())
			} else {
				holderSlot[key][pid] = len(file.Holders)
				file.Holders = append(file.Holders, model.DeletedFileHolder{PID: pid, Command: comm, FDs: []string{fd.Name()}})
			}
		}
	}

	// The largest holder is computed here, over every unique file, before
	// Files below is truncated to the largest few for the report -- a
	// process holding many just-under-the-cutoff files could otherwise be
	// invisible despite retaining more total space than the single largest
	// file's owner.
	holderPID, holderCommand, holderBytes, holderFileCount := largestHolder(order, files)

	reported := make([]model.DeletedFile, 0, len(order))
	for _, key := range order {
		f := *files[key]
		if f.Bytes >= minReportBytes {
			reported = append(reported, f)
		}
	}
	sort.Slice(reported, func(i, j int) bool { return reported[i].Bytes > reported[j].Bytes })
	if len(reported) > maxFiles {
		reported = reported[:maxFiles]
	}

	return collect.Data{DeletedFiles: &model.DeletedFiles{
		Available: true, TotalBytes: total, Files: reported,
		UniqueFiles: len(files), ProcessesHolding: len(holdingPIDs), TotalReferences: references,
		ProcessesScanned: scanned, ProcessesSkipped: skipped, ProcessesEligible: processesEligible,
		ProcessScanLimited: processesEligible > maxProcesses,
		LargestHolderPID:   holderPID, LargestHolderCommand: holderCommand,
		LargestHolderBytes: holderBytes, LargestHolderFileCount: holderFileCount,
	}}, nil
}

func countEligibleProcesses(entries []os.DirEntry) int {
	eligible := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err == nil {
			eligible++
		}
	}
	return eligible
}

// largestHolder sums, per process, the bytes of each unique file it holds
// (once per file regardless of how many fds reference it) and returns the
// process with the largest total. Ties break on the lower PID by iterating
// candidates in sorted order and keeping only strict improvements.
func largestHolder(order []inodeKey, files map[inodeKey]*model.DeletedFile) (pid int, command string, bytes uint64, fileCount int) {
	totals := make(map[int]uint64)
	counts := make(map[int]int)
	commands := make(map[int]string)
	for _, key := range order {
		f := files[key]
		for _, h := range f.Holders {
			totals[h.PID] += f.Bytes
			counts[h.PID]++
			if h.Command != "" {
				commands[h.PID] = h.Command
			}
		}
	}
	pids := make([]int, 0, len(totals))
	for p := range totals {
		pids = append(pids, p)
	}
	sort.Ints(pids)
	for _, p := range pids {
		if totals[p] > bytes {
			bytes, pid = totals[p], p
		}
	}
	return pid, commands[pid], bytes, counts[pid]
}

// allocatedBytes reports actual allocated filesystem space. st_blocks uses
// 512-byte units on Linux, and a valid zero value means a fully sparse or
// empty file consumes no disk blocks even when its logical size is enormous.
// Some filesystems include a small amount of extent/metadata overhead in
// st_blocks, so cap the result at the logical file size; this avoids reporting
// more file data than the inode can contain while preserving sparse-file
// accounting.
func allocatedBytes(stat *syscall.Stat_t) uint64 {
	allocated := uint64(stat.Blocks) * 512
	if stat.Size >= 0 && allocated > uint64(stat.Size) {
		return uint64(stat.Size)
	}
	return allocated
}

// formatDevice renders a raw dev_t as the familiar "major:minor" form (as
// lsof and /proc/self/mountinfo show it), using glibc's encoding of the
// 64-bit dev_t Linux stat syscalls return. This is display-only -- the
// dedup key uses the raw value directly -- so an encoding mismatch on some
// exotic platform would be cosmetic, never a correctness issue.
func formatDevice(dev uint64) string {
	major := uint32(((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000))
	minor := uint32((dev & 0xff) | ((dev >> 12) & 0xffffff00))
	return fmt.Sprintf("%d:%d", major, minor)
}

// onTmpfs reports whether the file behind fdPath lives on a tmpfs/shmem
// filesystem -- RAM-backed anonymous memory (memfd_create, /dev/shm), never
// real disk space, regardless of what its "(deleted)" name suggests.
func onTmpfs(statfs func(string, *syscall.Statfs_t) error, fdPath string) bool {
	var stat syscall.Statfs_t
	if err := statfs(fdPath, &stat); err != nil {
		return false
	}
	return stat.Type == tmpfsMagic
}

func readComm(root, pid string) string {
	data, err := os.ReadFile(filepath.Join(root, pid, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
