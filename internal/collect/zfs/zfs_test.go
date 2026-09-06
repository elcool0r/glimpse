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
