package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseMDStat(t *testing.T) {
	got := ParseMDStat("Personalities : [raid1]\nmd0 : active raid1 sda1[0] sdb1[1]\n      100000 blocks [2/2] [UU]\nmd1 : inactive sdc1[0]\n")
	if len(got) != 2 || got[0].State != "active" || got[0].Level != "1" || got[1].State != "inactive" {
		t.Fatalf("%+v", got)
	}
}

func TestParseMDStatDetectsDegradedMembers(t *testing.T) {
	got := ParseMDStat("md0 : active raid1 sda1[0] sdb1[1]\n      100000 blocks [2/2] [U_]\n")
	if len(got) != 1 || got[0].State != "degraded" {
		t.Fatalf("expected degraded array, got %+v", got)
	}
}

func TestParseMDStatLeavesInactiveLevelEmpty(t *testing.T) {
	got := ParseMDStat("md1 : inactive sdc1[0]\n")
	if len(got) != 1 || got[0].Level != "" {
		t.Fatalf("expected no RAID level for inactive array, got %+v", got)
	}
}

func TestParseLVMRows(t *testing.T) {
	if got := ParsePVs("/dev/sda2 | vg0 | a-- | 10.00g | 2.00g\n"); len(got) != 1 || got[0].SizeBytes == 0 || got[0].Group != "vg0" {
		t.Fatalf("%+v", got)
	}
	if got := ParseVGs("vg0 | wz--n- | 10.00g | 2.00g\n"); len(got) != 1 || got[0].Name != "vg0" {
		t.Fatalf("%+v", got)
	}
	if got := ParseLVs("root | vg0 | -wi-a----- | 8.00g\n"); len(got) != 1 || got[0].Group != "vg0" {
		t.Fatalf("%+v", got)
	}
}

func TestParseFstab(t *testing.T) {
	got := ParseFstab("# comment\nUUID=abc / ext4 defaults,noatime 0 1\n/swap.img none swap sw 0 0\n")
	if len(got) != 1 || got[0].MountPoint != "/" || len(got[0].Options) != 2 {
		t.Fatalf("%+v", got)
	}
}

// Attribute strings are positional bit fields whose case is significant.
// Reading them as a character set flagged healthy snapshot, origin and pvmove
// volumes, and folded LVM's uppercase "invalid" markers onto their healthy
// lowercase counterparts.
func TestLogicalVolumeAttributesAreRead(t *testing.T) {
	healthy := []string{
		"-wi-ao----", // linear, active, open
		"swi-a-s---", // snapshot
		"owi-a-s---", // snapshot origin
		"twi-aotz--", // thin pool
		"Vwi-a-tz--", // thin volume
		"rwi-a-r---", // raid
		"pwi-a-p---", // pvmove in progress
	}
	for _, attr := range healthy {
		if problem, reason := lvAttrProblem(attr); problem {
			t.Errorf("healthy volume %q flagged as %s", attr, reason)
		}
	}
	broken := map[string]string{
		"-wi-so----": "suspended",
		"swi-I-s---": "invalid snapshot",
		"-wi-ao--p-": "partial",
		"-wi-ao--X-": "unknown health",
		"-wi-Xo----": "unknown state",
	}
	for attr, want := range broken {
		problem, reason := lvAttrProblem(attr)
		if !problem || reason != want {
			t.Errorf("%q: problem=%v reason=%q want %q", attr, problem, reason, want)
		}
	}
}

func TestVolumeGroupAttributesAreRead(t *testing.T) {
	if problem, _ := vgAttrProblem("wz--n-"); problem {
		t.Error("healthy volume group flagged")
	}
	if problem, reason := vgAttrProblem("wz-pn-"); !problem || reason != "partial" {
		t.Errorf("partial group not detected: %v %q", problem, reason)
	}
	if problem, reason := vgAttrProblem("rz--n-"); !problem || reason != "read-only" {
		t.Errorf("read-only group not detected: %v %q", problem, reason)
	}
}

// lvm2 prints "<3.64t" for a value it rounded down. That is not a number, and
// every such volume silently reported a size of zero.
func TestParseSizeHandlesApproximationPrefixAndUnits(t *testing.T) {
	cases := map[string]uint64{
		"4001292484608": 4001292484608,
		"<3.64t":        4002222325104, // 3.64 TiB, the value lvm2 rounded down
		"100.00g":       100 << 30,
		">2.00m":        2 << 20,
		"512B":          512,
		"":              0,
		"not-a-size":    0,
	}
	for input, want := range cases {
		if got := parseSize(input); got != want {
			t.Errorf("parseSize(%q)=%d want %d", input, got, want)
		}
	}
}

// LVM tools need privileges on most distributions. Silently collecting nothing
// let an unprivileged run look like a host with no LVM problems.
func TestMissingLVMToolsAreReportedAsMissingCoverage(t *testing.T) {
	c := New()
	c.ProcRoot, c.EtcRoot = t.TempDir(), t.TempDir()
	c.lookPath = func(string) (string, error) { return "", errors.New("not installed") }
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Diagnostics) != 3 {
		t.Fatalf("missing LVM tools left no diagnostic: %+v", data.Diagnostics)
	}
}

func TestFailingLVMCommandIsReportedAsMissingCoverage(t *testing.T) {
	c := New()
	c.ProcRoot, c.EtcRoot = t.TempDir(), t.TempDir()
	c.lookPath = func(name string) (string, error) { return "/usr/sbin/" + name, nil }
	c.run = func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("permission denied")
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Diagnostics) != 1 || data.Diagnostics[0].Status != "info" || !strings.Contains(data.Diagnostics[0].Detail, "Run with sudo") {
		t.Fatalf("denied LVM query reported as success: %+v", data.Diagnostics)
	}
}

func TestLVMQueriesRequestByteUnits(t *testing.T) {
	c := New()
	c.ProcRoot, c.EtcRoot = t.TempDir(), t.TempDir()
	c.lookPath = func(name string) (string, error) { return name, nil }
	var seen [][]string
	c.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		seen = append(seen, args)
		return nil, nil
	}
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, args := range seen {
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "--units b") || !strings.Contains(joined, "--nosuffix") {
			t.Fatalf("display units still requested: %q", joined)
		}
	}
}
