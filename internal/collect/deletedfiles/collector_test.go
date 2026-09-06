package deletedfiles

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// newFakeProc builds a minimal /proc-shaped tree: one process with a comm
// file and an fd directory containing symlinks, some pointing at deleted
// targets and some not.
func newFakeProc(t *testing.T, pid string, comm string, deletedFile string, deletedSize int) string {
	t.Helper()
	root := t.TempDir()
	procDir := filepath.Join(root, pid)
	fdDir := filepath.Join(procDir, "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if comm != "" {
		if err := os.WriteFile(filepath.Join(procDir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A live, non-deleted regular file the fd "0" points at.
	livePath := filepath.Join(root, "live.txt")
	if err := os.WriteFile(livePath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(livePath, filepath.Join(fdDir, "0")); err != nil {
		t.Fatal(err)
	}
	if deletedFile != "" {
		// os.Readlink on a real symlink returns exactly what was written, so
		// this fakes the kernel's "target (deleted)" convention by pointing
		// the symlink at a path whose name literally ends that way. The
		// backing file is created sparse (Truncate, not actually written) so
		// a multi-gigabyte test size costs no real disk I/O or memory.
		backing := filepath.Join(root, filepath.Base(deletedFile)+" (deleted)")
		f, err := os.Create(backing)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(int64(deletedSize)); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(backing, filepath.Join(fdDir, "1")); err != nil {
			t.Fatal(err)
		}
	}
	// A socket-shaped, non-absolute target must never be mistaken for a
	// deleted file even if some odd path ended the same way.
	if err := os.Symlink("socket:[12345]", filepath.Join(fdDir, "2")); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCollectFindsDeletedFileAboveThreshold(t *testing.T) {
	root := newFakeProc(t, "123", "leaky-app", "/var/log/app.log", 2<<20) // 2 MiB, above minReportBytes
	c := &Collector{procRoot: root}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	df := data.DeletedFiles
	if df == nil || !df.Available {
		t.Fatalf("expected an available result, got %+v", df)
	}
	if df.TotalBytes != 2<<20 {
		t.Fatalf("total bytes = %d, want %d", df.TotalBytes, 2<<20)
	}
	if len(df.Handles) != 1 || df.Handles[0].PID != 123 || df.Handles[0].Command != "leaky-app" {
		t.Fatalf("unexpected handles: %+v", df.Handles)
	}
	if df.ProcessesScanned != 1 {
		t.Fatalf("processes scanned = %d, want 1", df.ProcessesScanned)
	}
}

func TestCollectIgnoresSmallDeletedFiles(t *testing.T) {
	root := newFakeProc(t, "456", "tiny", "/tmp/x", 100) // well under minReportBytes
	c := &Collector{procRoot: root}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(data.DeletedFiles.Handles) != 0 {
		t.Fatalf("expected no reported handles for a tiny deleted file, got %+v", data.DeletedFiles.Handles)
	}
	// Still counted toward the total even if not individually listed.
	if data.DeletedFiles.TotalBytes != 100 {
		t.Fatalf("total bytes = %d, want 100", data.DeletedFiles.TotalBytes)
	}
}

func TestCollectSkipsNonPIDEntriesAndReportsUnavailableWithoutProcRoot(t *testing.T) {
	c := &Collector{procRoot: filepath.Join(t.TempDir(), "does-not-exist")}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(data.Diagnostics) != 1 || data.Diagnostics[0].Status != "unavailable" {
		t.Fatalf("expected an unavailable diagnostic, got %+v", data.Diagnostics)
	}
}

// A memfd_create() object (the .NET runtime's JIT "doublemapper", among
// others) shows up in /proc exactly like a deleted regular file, "(deleted)"
// suffix included, but lives on tmpfs/shmem and is not disk-backed. Its
// logical size can be enormous (a virtual/maximum extent, not real usage),
// so counting it here would both wildly overcount and point at the wrong
// remediation.
func TestCollectExcludesTmpfsBackedMemfd(t *testing.T) {
	root := newFakeProc(t, "789", "jellyfin", "/memfd:doublemapper", 2<<30) // 2 GiB logical size
	c := &Collector{
		procRoot: root,
		statfs: func(path string, stat *syscall.Statfs_t) error {
			if filepath.Base(path) == "1" { // the deleted-memfd fd from newFakeProc
				stat.Type = tmpfsMagic
			}
			return nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.DeletedFiles.TotalBytes != 0 || len(data.DeletedFiles.Handles) != 0 {
		t.Fatalf("expected the tmpfs-backed memfd to be excluded entirely, got %+v", data.DeletedFiles)
	}
}

func TestOnTmpfsReturnsFalseOnStatfsError(t *testing.T) {
	if onTmpfs(func(string, *syscall.Statfs_t) error { return os.ErrNotExist }, "/does/not/matter") {
		t.Fatal("a statfs error must not be treated as tmpfs")
	}
}

func TestNameIsDeletedFiles(t *testing.T) {
	if (&Collector{}).Name() != "deleted-files" {
		t.Fatalf("unexpected name: %s", (&Collector{}).Name())
	}
}
