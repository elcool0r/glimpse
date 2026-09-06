package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestParseMountInfo(t *testing.T) {
	input := "36 25 0:32 / / rw,relatime - ext4 /dev/sda1 rw\n37 36 0:45 / /run/user/1000 rw,nosuid - tmpfs tmpfs rw\n38 25 0:20 / /proc rw,nosuid - proc proc rw\n39 25 0:46 / /srv\\040data ro,relatime - xfs /dev/sdb1 ro\n"
	mounts, err := ParseMountInfo(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 4 || mounts[3].Target != "/srv data" || !mounts[3].ReadOnly {
		t.Fatalf("unexpected mounts: %#v", mounts)
	}
	if !IsReal(mounts[0]) || IsReal(mounts[1]) || IsReal(mounts[2]) {
		t.Fatalf("wrong real filesystem classification")
	}
}

func TestParseMountInfoRejectsMalformed(t *testing.T) {
	if _, err := ParseMountInfo(strings.NewReader("broken\n")); err == nil {
		t.Fatal("expected error")
	}
}

func TestIsRealIncludesOnlyRootOverlay(t *testing.T) {
	if !IsReal(Mount{Type: "overlay", Target: "/"}) {
		t.Fatal("root overlay should be included")
	}
	if IsReal(Mount{Type: "overlay", Target: "/var/lib"}) {
		t.Fatal("non-root overlay should be excluded")
	}
}

func TestPotentiallyBlockingFilesystemsAreNeverProbed(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "self"), 0755); err != nil {
		t.Fatal(err)
	}
	input := "1 0 0:1 / /remote rw - nfs remote:/data rw\n2 0 0:2 / /fuse rw - fuse.sshfs host:/data rw\n3 0 0:3 / /cluster rw - ocfs2 /dev/sdc rw\n4 0 0:4 / /local rw - ext4 /dev/sda rw\n"
	if err := os.WriteFile(filepath.Join(root, "self", "mountinfo"), []byte(input), 0644); err != nil {
		t.Fatal(err)
	}
	var calls []string
	result, err := collectWithStatfs(context.Background(), root, func(path string, st *syscall.Statfs_t) error {
		calls = append(calls, path)
		st.Bsize = 4096
		st.Blocks = 100
		st.Bfree = 50
		return nil
	})
	if err != nil || len(result) != 1 || len(calls) != 1 || calls[0] != "/local" {
		t.Fatalf("calls=%v result=%v err=%v", calls, result, err)
	}
}

// Capacity is measured against space a normal process can use, which is what
// df reports. Dividing by total capacity counts the root reserve as free, so a
// default ext4 read several points more optimistic than df and the "nearly
// full" threshold landed only after unprivileged writes had begun failing.
func TestUsedFractionExcludesTheRootReserve(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	input := "1 0 0:1 / /data rw - ext4 /dev/sda rw\n"
	if err := os.WriteFile(filepath.Join(root, "self", "mountinfo"), []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	const blocks, reserve = 100000, 5000
	result, err := collectWithStatfs(context.Background(), root, func(_ string, st *syscall.Statfs_t) error {
		st.Bsize = 4096
		st.Blocks = blocks
		st.Bfree = reserve // full for every unprivileged process
		st.Bavail = 0
		return nil
	})
	if err != nil || len(result) != 1 {
		t.Fatalf("result=%v err=%v", result, err)
	}
	if got := result[0].UsedFraction; got != 1 {
		t.Fatalf("used fraction=%.4f, want 1.0 when no space is available (df would say 100%%)", got)
	}
}
