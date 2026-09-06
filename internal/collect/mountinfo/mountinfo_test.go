package mountinfo

import (
	"strings"
	"testing"
)

func TestParseHandlesOptionalFieldsAndEscapes(t *testing.T) {
	input := strings.Join([]string{
		"36 25 0:32 / / rw,relatime shared:1 - ext4 /dev/sda1 rw",
		`39 25 0:46 / /srv\040data ro,relatime - xfs /dev/sdb1 ro`,
		"41 25 0:50 / /mnt/nfs rw master:2 propagate_from:1 - nfs4 server:/export rw",
	}, "\n")
	entries, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries=%+v", entries)
	}
	if entries[1].Target != "/srv data" || !entries[1].ReadOnly || entries[1].Type != "xfs" {
		t.Fatalf("escape or field mapping wrong: %+v", entries[1])
	}
	if entries[2].Type != "nfs4" || entries[2].Source != "server:/export" {
		t.Fatalf("optional fields shifted the separator: %+v", entries[2])
	}
}

// One unreadable record must not remove every mount from the report.
func TestParseSkipsMalformedRecords(t *testing.T) {
	input := "garbage\n36 25 0:32 / / rw,relatime - ext4 /dev/sda1 rw\n"
	entries, err := Parse(strings.NewReader(input))
	if err != nil || len(entries) != 1 || entries[0].Target != "/" {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	if _, err := Parse(strings.NewReader("garbage\n")); err == nil {
		t.Fatal("a file with no readable record should fail")
	}
}

// The separator search starts after the fixed fields, so a mount point that is
// literally "-" cannot be mistaken for it.
func TestParseIgnoresDashMountPoint(t *testing.T) {
	entries, err := Parse(strings.NewReader("36 25 0:32 / - rw,relatime - ext4 /dev/sda1 rw\n"))
	if err != nil || len(entries) != 1 || entries[0].Target != "-" || entries[0].Type != "ext4" {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
}
