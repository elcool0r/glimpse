package deletedfiles

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// notTmpfsStatfs always reports a non-tmpfs filesystem type (ext4's magic
// number). Tests use it so their outcome does not depend on whether the
// host happens to run this test under a tmpfs-mounted TMPDIR (common on
// Linux CI), which would otherwise silently exclude every fixture file.
func notTmpfsStatfs(string, *syscall.Statfs_t) error { return nil }

// addProcess creates a minimal /proc/<pid> directory with a comm file and
// an empty fd directory, returning the fd directory path.
func addProcess(t *testing.T, root, pid, comm string) string {
	t.Helper()
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
	return fdDir
}

// backingFile creates a file elsewhere in root (not under any /proc/<pid>
// directory) that plays the role of a deleted inode's remaining data. Two
// fd symlinks pointing at the *same* backingFile path share the same real
// (dev, ino), exactly like two fds referencing one unlinked inode on a real
// system. real controls whether actual bytes are written (giving accurate
// st_blocks for size-sensitive tests) or the file is only truncated to
// length, sparse (for the dedicated sparse-file test).
func backingFile(t *testing.T, root, name string, size int64, real bool) string {
	t.Helper()
	path := filepath.Join(root, name+" (deleted)")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if real {
		if _, err := f.Write(make([]byte, size)); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	return path
}

// linkFD symlinks <fdDir>/<fd> to target, faking the kernel's convention of
// appending " (deleted)" to the target name of an fd whose file was
// unlinked (target must already end that way; see backingFile).
func linkFD(t *testing.T, fdDir, fd, target string) {
	t.Helper()
	if err := os.Symlink(target, filepath.Join(fdDir, fd)); err != nil {
		t.Fatal(err)
	}
}

func TestCollectOneFileOneFD(t *testing.T) {
	root := t.TempDir()
	fdDir := addProcess(t, root, "100", "app")
	target := backingFile(t, root, "a", 2<<20, true)
	linkFD(t, fdDir, "5", target)

	c := &Collector{procRoot: root, statfs: notTmpfsStatfs}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	df := data.DeletedFiles
	if df.TotalBytes != 2<<20 {
		t.Fatalf("total = %d, want %d", df.TotalBytes, 2<<20)
	}
	if df.UniqueFiles != 1 || df.TotalReferences != 1 || df.ProcessesHolding != 1 {
		t.Fatalf("unique=%d refs=%d holding=%d, want 1/1/1", df.UniqueFiles, df.TotalReferences, df.ProcessesHolding)
	}
	if len(df.Files) != 1 || len(df.Files[0].Holders) != 1 || len(df.Files[0].Holders[0].FDs) != 1 {
		t.Fatalf("unexpected files: %+v", df.Files)
	}
}

// One process holding the same deleted file on three separate fds (the
// motivating real-world case: podman/journald reopening its own journal
// segment) must count that file's space once, not three times, while still
// recording all three fds as evidence.
func TestCollectSameFileMultipleFDsSameProcess(t *testing.T) {
	root := t.TempDir()
	fdDir := addProcess(t, root, "200", "podman")
	target := backingFile(t, root, "journal", 128<<20, true)
	linkFD(t, fdDir, "135", target)
	linkFD(t, fdDir, "198", target)
	linkFD(t, fdDir, "302", target)

	c := &Collector{procRoot: root, statfs: notTmpfsStatfs}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	df := data.DeletedFiles
	if df.TotalBytes != 128<<20 {
		t.Fatalf("total = %d, want %d (space must be counted once, not per fd)", df.TotalBytes, 128<<20)
	}
	if df.UniqueFiles != 1 {
		t.Fatalf("unique files = %d, want 1", df.UniqueFiles)
	}
	if df.TotalReferences != 3 {
		t.Fatalf("references = %d, want 3 (all fds should still be recorded)", df.TotalReferences)
	}
	if len(df.Files) != 1 || len(df.Files[0].Holders) != 1 {
		t.Fatalf("expected one file with one holder, got %+v", df.Files)
	}
	if len(df.Files[0].Holders[0].FDs) != 3 {
		t.Fatalf("expected all 3 fds recorded on the one holder, got %+v", df.Files[0].Holders[0])
	}
}

// The same deleted file held open by two different processes: global space
// is still counted once, but both processes must appear as holders.
func TestCollectSameFileMultipleProcesses(t *testing.T) {
	root := t.TempDir()
	target := backingFile(t, root, "shared", 50<<20, true)
	fdDirA := addProcess(t, root, "300", "writer")
	linkFD(t, fdDirA, "9", target)
	fdDirB := addProcess(t, root, "301", "reader")
	linkFD(t, fdDirB, "4", target)

	c := &Collector{procRoot: root, statfs: notTmpfsStatfs}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	df := data.DeletedFiles
	if df.TotalBytes != 50<<20 {
		t.Fatalf("total = %d, want %d (shared file must be counted once globally)", df.TotalBytes, 50<<20)
	}
	if df.ProcessesHolding != 2 {
		t.Fatalf("processes holding = %d, want 2", df.ProcessesHolding)
	}
	if len(df.Files) != 1 || len(df.Files[0].Holders) != 2 {
		t.Fatalf("expected one file with two holders, got %+v", df.Files)
	}
}

// Two distinct deleted files that happen to be the same size must not be
// merged into one.
func TestCollectDistinctFilesSameSizeNotMerged(t *testing.T) {
	root := t.TempDir()
	fdDir := addProcess(t, root, "400", "app")
	targetA := backingFile(t, root, "file-a", 10<<20, true)
	targetB := backingFile(t, root, "file-b", 10<<20, true)
	linkFD(t, fdDir, "3", targetA)
	linkFD(t, fdDir, "4", targetB)

	c := &Collector{procRoot: root, statfs: notTmpfsStatfs}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	df := data.DeletedFiles
	if df.UniqueFiles != 2 {
		t.Fatalf("unique files = %d, want 2 (same size must not merge distinct files)", df.UniqueFiles)
	}
	if df.TotalBytes != 20<<20 {
		t.Fatalf("total = %d, want %d", df.TotalBytes, 20<<20)
	}
}

// Two distinct deleted files with identical (or similar) basenames must not
// be merged by path -- only (dev, ino) identifies a file.
func TestCollectDistinctFilesSamePathNotMergedByName(t *testing.T) {
	root := t.TempDir()
	fdDir := addProcess(t, root, "500", "app")
	// Two different backing files, but linked from paths that share the
	// exact same display name once "(deleted)" is stripped, by naming both
	// symlink targets so os.Readlink returns the same logical path string
	// for each even though they are different underlying files.
	dirA := filepath.Join(root, "a")
	dirB := filepath.Join(root, "b")
	if err := os.MkdirAll(dirA, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dirB, 0o755); err != nil {
		t.Fatal(err)
	}
	targetA := filepath.Join(dirA, "same-name.log (deleted)")
	targetB := filepath.Join(dirB, "same-name.log (deleted)")
	for _, p := range []string{targetA, targetB} {
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(make([]byte, 5<<20)); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	linkFD(t, fdDir, "6", targetA)
	linkFD(t, fdDir, "7", targetB)

	c := &Collector{procRoot: root, statfs: notTmpfsStatfs}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.DeletedFiles.UniqueFiles != 2 {
		t.Fatalf("unique files = %d, want 2 (identical display path must not merge distinct inodes)", data.DeletedFiles.UniqueFiles)
	}
}

// A sparse deleted file's allocated space (st_blocks) should be reported,
// not its logical length, when the two differ.
func TestCollectSparseFileReportsAllocatedNotLogical(t *testing.T) {
	root := t.TempDir()
	fdDir := addProcess(t, root, "600", "app")
	const logicalSize = 200 << 20 // 200 MiB logical, never written
	target := backingFile(t, root, "sparse", logicalSize, false)
	linkFD(t, fdDir, "8", target)

	c := &Collector{procRoot: root, statfs: notTmpfsStatfs}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	got := data.DeletedFiles.TotalBytes
	if got >= logicalSize {
		// Sparse-file support (a Truncate() past the current end-of-file
		// allocating no blocks for the hole) is a property of the
		// underlying filesystem, not of this code -- some filesystems used
		// for a test's TempDir do not exhibit it. The allocated-vs-logical
		// preference itself is still exercised by allocatedBytes directly
		// having a Blocks field to prefer; this only skips the end-to-end
		// assertion when the host filesystem does not cooperate.
		t.Skipf("host filesystem allocated the full %d bytes for a truncated file (no sparse support observed); cannot exercise the allocated-vs-logical distinction here", logicalSize)
	}
	if got != 0 || len(data.DeletedFiles.Files) != 0 {
		t.Fatalf("sparse file consumed %d bytes and reported %+v; want no allocated disk space", got, data.DeletedFiles.Files)
	}
}

// The already-fixed memfd/tmpfs exclusion must keep working: a tmpfs-backed
// "deleted" object is not disk space and must not appear at all, regardless
// of its (typically huge, virtual) logical size.
func TestCollectExcludesTmpfsBackedMemfd(t *testing.T) {
	root := t.TempDir()
	fdDir := addProcess(t, root, "700", "jellyfin")
	target := backingFile(t, root, "memfd:doublemapper", 2<<30, false)
	linkFD(t, fdDir, "9", target)

	c := &Collector{
		procRoot: root,
		statfs: func(path string, stat *syscall.Statfs_t) error {
			if filepath.Base(path) == "9" {
				stat.Type = tmpfsMagic
			}
			return nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.DeletedFiles.TotalBytes != 0 || len(data.DeletedFiles.Files) != 0 || data.DeletedFiles.UniqueFiles != 0 {
		t.Fatalf("expected the tmpfs-backed memfd to be excluded entirely, got %+v", data.DeletedFiles)
	}
}

// The exact scenario from the /tmp/glimpse-deleted-test integration check:
// a single ~100 MiB deleted file still held open by one process.
func TestCollectMatchesDeletedTestIntegrationScenario(t *testing.T) {
	root := t.TempDir()
	fdDir := addProcess(t, root, "800", "tail")
	target := backingFile(t, root, "glimpse-deleted-test", 100<<20, true)
	linkFD(t, fdDir, "3", target)

	c := &Collector{procRoot: root, statfs: notTmpfsStatfs}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.DeletedFiles.TotalBytes != 100<<20 {
		t.Fatalf("total = %d, want ~100 MiB", data.DeletedFiles.TotalBytes)
	}
}

func TestCollectIgnoresSmallDeletedFiles(t *testing.T) {
	root := t.TempDir()
	fdDir := addProcess(t, root, "900", "tiny")
	target := backingFile(t, root, "x", 100, true)
	linkFD(t, fdDir, "3", target)

	c := &Collector{procRoot: root, statfs: notTmpfsStatfs}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(data.DeletedFiles.Files) != 0 {
		t.Fatalf("expected no reported files for a tiny deleted file, got %+v", data.DeletedFiles.Files)
	}
	// Still counted toward the total even though not individually listed.
	// The exact value is whatever the filesystem allocates for a 100-byte
	// write (typically one block, e.g. 4096 bytes) -- allocated space, not
	// the logical 100, is the intended accounting -- so this only checks
	// that it was counted at all and stayed well under minReportBytes.
	if data.DeletedFiles.TotalBytes == 0 || data.DeletedFiles.TotalBytes >= minReportBytes {
		t.Fatalf("total bytes = %d, want a small nonzero allocation under %d", data.DeletedFiles.TotalBytes, minReportBytes)
	}
}

func TestCollectReportsUnavailableWithoutProcRoot(t *testing.T) {
	c := &Collector{procRoot: filepath.Join(t.TempDir(), "does-not-exist")}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(data.Diagnostics) != 1 || data.Diagnostics[0].Status != "unavailable" {
		t.Fatalf("expected an unavailable diagnostic, got %+v", data.Diagnostics)
	}
}

func TestCollectReportsBoundedProcessCoverage(t *testing.T) {
	root := t.TempDir()
	for pid := 1; pid <= maxProcesses+1; pid++ {
		if err := os.Mkdir(filepath.Join(root, strconv.Itoa(pid)), 0o755); err != nil {
			t.Fatalf("mkdir process %d: %v", pid, err)
		}
	}
	c := &Collector{procRoot: root, statfs: notTmpfsStatfs}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	got := data.DeletedFiles
	if got.ProcessesEligible != maxProcesses+1 || !got.ProcessScanLimited {
		t.Fatalf("coverage=%+v", got)
	}
	if got.ProcessesScanned+got.ProcessesSkipped != maxProcesses {
		t.Fatalf("scanned=%d skipped=%d, want bounded total %d", got.ProcessesScanned, got.ProcessesSkipped, maxProcesses)
	}
}

func TestLargestHolderAttributesUniqueFilesNotReferences(t *testing.T) {
	root := t.TempDir()
	// pid 1: one 300 MiB file held on three fds (should count once).
	fdDir1 := addProcess(t, root, "1000", "big-single")
	bigFile := backingFile(t, root, "big", 300<<20, true)
	linkFD(t, fdDir1, "1", bigFile)
	linkFD(t, fdDir1, "2", bigFile)
	linkFD(t, fdDir1, "3", bigFile)
	// pid 2: two distinct 150 MiB files (totals the same 300 MiB, but across
	// two unique files instead of fd duplication).
	fdDir2 := addProcess(t, root, "1001", "many-small")
	linkFD(t, fdDir2, "1", backingFile(t, root, "small-a", 150<<20, true))
	linkFD(t, fdDir2, "2", backingFile(t, root, "small-b", 150<<20, true))

	c := &Collector{procRoot: root, statfs: notTmpfsStatfs}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	df := data.DeletedFiles
	if df.LargestHolderBytes != 300<<20 {
		t.Fatalf("largest holder bytes = %d, want %d", df.LargestHolderBytes, 300<<20)
	}
	// Both processes retain the same total; the lower PID (1000) must win
	// the deterministic tie-break.
	if df.LargestHolderPID != 1000 {
		t.Fatalf("largest holder pid = %d, want 1000 (lower pid wins ties)", df.LargestHolderPID)
	}
	if df.LargestHolderFileCount != 1 {
		t.Fatalf("largest holder file count = %d, want 1 (three fds on one file is one unique file)", df.LargestHolderFileCount)
	}
}

// Deterministic, filesystem-independent coverage of the allocated-vs-logical
// preference: TestCollectSparseFileReportsAllocatedNotLogical exercises the
// same logic end to end but can only observe it on a filesystem that
// actually supports sparse files.
func TestAllocatedBytesUsesBlocksWithoutLogicalFallback(t *testing.T) {
	sparse := &syscall.Stat_t{Blocks: 0}
	if got := allocatedBytes(sparse); got != 0 {
		t.Fatalf("with zero blocks, want zero allocated bytes: got %d", got)
	}
	allocated := &syscall.Stat_t{Blocks: 8} // 8 * 512 = 4096 bytes allocated
	if got := allocatedBytes(allocated); got != 4096 {
		t.Fatalf("allocatedBytes = %d, want 4096 (st_blocks*512), not the 200 MiB logical size", got)
	}
}

func TestOnTmpfsReturnsFalseOnStatfsError(t *testing.T) {
	if onTmpfs(func(string, *syscall.Statfs_t) error { return os.ErrNotExist }, "/does/not/matter") {
		t.Fatal("a statfs error must not be treated as tmpfs")
	}
}

// makedev mirrors glibc's gnu_dev_makedev, the inverse of formatDevice's
// gnu_dev_major/gnu_dev_minor, so the test constructs a raw dev_t the same
// way the real encoding does rather than an arbitrary bit pattern.
func makedev(major, minor uint32) uint64 {
	return uint64(minor&0xff) | uint64(major&0xfff)<<8 |
		uint64(minor&^uint32(0xff))<<12 | uint64(major&^uint32(0xfff))<<32
}

func TestFormatDevice(t *testing.T) {
	dev := makedev(253, 3)
	got := formatDevice(dev)
	if got != "253:3" {
		t.Fatalf("formatDevice(%d) = %q, want %q", dev, got, "253:3")
	}
}

func TestNameIsDeletedFiles(t *testing.T) {
	if (&Collector{}).Name() != "deleted-files" {
		t.Fatalf("unexpected name: %s", (&Collector{}).Name())
	}
}
