package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestBindMountsCountAsOneFilesystem covers the noise source that made one
// full device read as several independent problems: statfs returns identical
// capacity for every bind mount, so deduplicating by mount point turned a
// single full filesystem into one "nearly full" critical per mount.
func TestBindMountsCountAsOneFilesystem(t *testing.T) {
	const mountinfo = `` +
		"25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
		"26 25 8:1 / /srv/data rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
		"27 25 8:1 / /var/backup rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
		// A different subtree of the same device is still the same capacity,
		// but it is a distinct mount an operator may care about, so it is kept.
		"28 25 8:1 /home /export/home rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
		"29 25 8:16 / /mnt/other rw,relatime shared:2 - ext4 /dev/sdb rw\n" +
		// Stacked mounts: two different devices at one path, as /dev/shm and
		// /dev/pts commonly are. statfs is keyed on the path and can only
		// return the topmost mount's answer, so counting both would report the
		// same capacity twice under two device identities.
		"30 25 0:50 / /stacked rw,relatime shared:3 - tmpfs tmpfs rw\n" +
		"31 25 0:51 / /stacked rw,relatime shared:4 - tmpfs tmpfs rw\n"

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "self", "mountinfo"), []byte(mountinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	statfs := func(_ string, out *syscall.Statfs_t) error {
		out.Bsize = 4096
		out.Blocks = 1000
		out.Bfree = 10
		out.Bavail = 10
		out.Files = 100
		out.Ffree = 90
		return nil
	}
	usages, err := collectWithStatfs(context.Background(), root, statfs)
	if err != nil {
		t.Fatal(err)
	}
	targets := make([]string, 0, len(usages))
	for _, u := range usages {
		targets = append(targets, u.Mount.Target)
	}
	// "/" and its two bind mounts collapse to one entry, the two stacked
	// mounts at /stacked collapse to one, and the /home subtree mount and the
	// separate device remain.
	if len(usages) != 4 {
		t.Fatalf("got %d filesystems (%v), want 4: bind mounts of one device and stacked mounts at one path must each be counted once", len(usages), targets)
	}
	want := map[string]bool{"/": true, "/export/home": true, "/mnt/other": true, "/stacked": true}
	for _, target := range targets {
		if !want[target] {
			t.Errorf("unexpected filesystem %q in %v", target, targets)
		}
	}
}

// TestMountsWithoutDeviceIDStillDeduplicateByTarget keeps hand-built fixtures
// and any future non-mountinfo source behaving as they did before.
func TestMountsWithoutDeviceIDStillDeduplicateByTarget(t *testing.T) {
	a := Mount{Target: "/data", Type: "ext4"}
	b := Mount{Target: "/data", Type: "ext4"}
	c := Mount{Target: "/other", Type: "ext4"}
	if mountKey(a) != mountKey(b) {
		t.Error("identical targets without a device ID must share a key")
	}
	if mountKey(a) == mountKey(c) {
		t.Error("different targets without a device ID must not share a key")
	}
}
