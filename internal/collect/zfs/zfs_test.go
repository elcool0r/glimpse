package zfs

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseStatus(t *testing.T) {
	raw := `  pool: tank
 state: DEGRADED
  scan: scrub in progress since Thu
config:

        NAME        STATE     READ WRITE CKSUM
        tank        DEGRADED     1     2     3
          mirror-0  DEGRADED     1     2     3

errors: Permanent errors have been detected in the following files:
  pool: safe
 state: ONLINE
config:
        NAME        STATE     READ WRITE CKSUM
        safe        ONLINE       0     0     0
errors: No known data errors
`
	got := ParseStatus(raw)
	if len(got) != 2 || got[0].Name != "safe" || got[1].ReadErrors != 1 || !got[1].PermanentErrors || got[0].PermanentErrors {
		t.Fatalf("%+v", got)
	}
}

func TestParseStatusPreservesScanDetails(t *testing.T) {
	got := ParseStatus(`pool: tank
 state: ONLINE
 scan: scrub repaired 0B in 00:12:34 with 0 errors on Sun Sep  6 12:00:00 2026
config:
        NAME        STATE     READ WRITE CKSUM
        tank        ONLINE       0     0     0
errors: No known data errors
`)
	if len(got) != 1 || got[0].Health != "ONLINE" || !strings.HasPrefix(got[0].ScanState, "scrub repaired 0B") {
		t.Fatalf("pool=%+v", got)
	}
}

func TestCollectKeepsPoolsWhenZpoolReturnsStatusError(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "/sbin/zpool", nil },
		inUse:    func() bool { return true },
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("pool: tank\n state: DEGRADED\n scan: scrub in progress\nconfig:\n tank DEGRADED 0 0 0\nerrors: No known data errors\n"), errors.New("exit status 1")
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil || len(data.ZFSPools) != 1 || data.ZFSPools[0].Health != "DEGRADED" {
		t.Fatalf("data=%+v err=%v", data, err)
	}
	if len(data.Diagnostics) != 1 || data.Diagnostics[0].Status != "error" {
		t.Fatalf("diagnostics=%+v", data.Diagnostics)
	}
}

func TestCollectSkipsWhenZFSIsNotInUse(t *testing.T) {
	called := false
	c := &Collector{
		inUse:    func() bool { return false },
		lookPath: func(string) (string, error) { called = true; return "/sbin/zpool", nil },
	}
	data, err := c.Collect(context.Background())
	if err != nil || called || data.ZFSPools != nil || len(data.Diagnostics) != 0 {
		t.Fatalf("zfs check was not skipped: data=%+v err=%v called=%v", data, err, called)
	}
}

func TestScanProgressContinuation(t *testing.T) {
	pools := ParseStatus(`pool: tank
 state: ONLINE
 scan: scrub in progress since Fri Sep 4 00:00:00 2026
   10G scanned at 1G/s, 2G issued at 200M/s, 100G total
   0B repaired, 2.00% done, 00:08:00 to go
config:
 NAME STATE READ WRITE CKSUM
 tank ONLINE 0 0 0
errors: No known data errors
`)
	if len(pools) != 1 || !strings.Contains(pools[0].ScanState, "2.00% done") || strings.Contains(pools[0].ScanState, "config:") {
		t.Fatalf("%+v", pools)
	}
}

func TestParseStatusRetainsLeafAndAggregateEvidenceWithoutSumming(t *testing.T) {
	for _, layout := range []string{"mirror-0", "raidz1-0"} {
		t.Run(layout, func(t *testing.T) {
			pools := ParseStatus("pool: tank\n state: ONLINE\nconfig:\n" +
				"        NAME        STATE     READ WRITE CKSUM\n" +
				"        tank        ONLINE       0     0     0\n" +
				"          " + layout + "  DEGRADED     5     0     0\n" +
				"            /dev/sda ONLINE       5     0     0\n" +
				"            /dev/sdb ONLINE       0     0     7\n" +
				"errors: No known data errors\n")
			if len(pools) != 1 || len(pools[0].VdevErrors) != 3 {
				t.Fatalf("pool=%+v", pools)
			}
			if pools[0].ReadErrors != 0 || pools[0].WriteErrors != 0 || pools[0].ChecksumErrors != 0 {
				t.Fatalf("pool row counters changed: %+v", pools[0])
			}
			if got := pools[0].VdevErrors; got[0].Name != layout || got[0].ReadErrors != 5 || got[1].Name != "/dev/sda" || got[1].ReadErrors != 5 || got[2].Name != "/dev/sdb" || got[2].ChecksumErrors != 7 {
				t.Fatalf("vdev evidence changed: %+v", got)
			}
		})
	}
}

func TestParseStatusScaledCountersAreNonzeroAndApproximate(t *testing.T) {
	pools := ParseStatus("pool: tank\n state: ONLINE\nconfig:\n tank ONLINE 1.23K 0 0\nerrors: No known data errors\n")
	if len(pools) != 1 || pools[0].ReadErrors == 0 || !pools[0].Approximate {
		t.Fatalf("scaled counter lost: %+v", pools)
	}
	pools = ParseStatus("pool: tank\n state: ONLINE\nconfig:\n tank ONLINE 0 0 0\n /dev/sda ONLINE 0 0 1.23K\nerrors: No known data errors\n")
	if len(pools) != 1 || len(pools[0].VdevErrors) != 1 || pools[0].VdevErrors[0].ChecksumErrors == 0 || !pools[0].VdevErrors[0].Approximate {
		t.Fatalf("scaled leaf counter lost: %+v", pools)
	}
}

func TestParseStatusCounterBoundaries(t *testing.T) {
	max := "18446744073709551615"
	if value, approximate, ok := parseCounter(max); !ok || approximate || value != ^uint64(0) {
		t.Fatalf("max literal: value=%d approximate=%v ok=%v", value, approximate, ok)
	}
	for _, value := range []string{"NaN", "+Inf", "-Inf", "18446744073709551616K"} {
		if parsed, _, ok := parseCounter(value); ok || parsed != 0 {
			t.Fatalf("invalid counter %q parsed as %d (ok=%v)", value, parsed, ok)
		}
	}
}

func TestCollectRequestsLiteralStatusCounters(t *testing.T) {
	var args []string
	c := &Collector{lookPath: func(string) (string, error) { return "zpool", nil }, inUse: func() bool { return true }, run: func(_ context.Context, _ string, got ...string) ([]byte, error) {
		args = got
		return []byte("pool: tank\n state: ONLINE\nconfig:\n tank ONLINE 0 0 0\nerrors: No known data errors\n"), nil
	}}
	if _, err := c.Collect(context.Background()); err != nil || strings.Join(args, " ") != "status -P -p" {
		t.Fatalf("args=%v err=%v", args, err)
	}
}
