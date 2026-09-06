// Package deletedfiles finds file descriptors still open on deleted
// (unlinked) files -- the classic "df says the disk is full but nothing on
// it looks large" symptom. A process that keeps writing to a file after it
// has been unlinked (a rotated log an old process handle still points at, a
// crashed cleanup job, a long-running download to a file that got removed
// mid-transfer) keeps that data occupying real disk space until every
// process holding the descriptor closes it or exits; nothing in a normal
// directory listing shows it.
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
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

const (
	defaultProcRoot = "/proc"
	// minReportBytes ignores small deleted-but-open files (a log rotated a
	// moment before the writer noticed, a temp file mid-cleanup): common,
	// harmless, and not what this check exists to catch.
	minReportBytes = 1 << 20 // 1 MiB
	// maxHandles keeps the report to the largest offenders rather than every
	// match, which can otherwise run into the hundreds on a busy host.
	maxHandles = 10
	// maxProcesses bounds the scan on a host running many thousands of
	// processes; this is a health snapshot, not an exhaustive audit.
	maxProcesses = 4096
)

type Collector struct {
	procRoot string
}

func New() *Collector { return &Collector{procRoot: defaultProcRoot} }

func (c *Collector) Name() string { return "deleted-files" }

// Static marks this as a gauge: one bounded scan, not a sampled counter
// needing two boundaries.
func (c *Collector) Static() {}

func (c *Collector) Collect(ctx context.Context) (collect.Data, error) {
	root := c.procRoot
	if root == "" {
		root = defaultProcRoot
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "proc: " + err.Error()}}}, nil
	}

	var handles []model.DeletedFileHandle
	var total uint64
	scanned, skipped := 0, 0
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
			size := uint64(info.Size())
			total += size
			if size >= minReportBytes {
				handles = append(handles, model.DeletedFileHandle{
					PID: pid, Command: comm, Path: strings.TrimSuffix(target, " (deleted)"), Bytes: size,
				})
			}
		}
	}

	sort.Slice(handles, func(i, j int) bool { return handles[i].Bytes > handles[j].Bytes })
	if len(handles) > maxHandles {
		handles = handles[:maxHandles]
	}

	return collect.Data{DeletedFiles: &model.DeletedFiles{
		Available: true, TotalBytes: total, Handles: handles,
		ProcessesScanned: scanned, ProcessesSkipped: skipped,
	}}, nil
}

func readComm(root, pid string) string {
	data, err := os.ReadFile(filepath.Join(root, pid, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
