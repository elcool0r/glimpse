package network

import (
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
)

// A modern kernel header. Values are hex with no prefix and there is one row
// per CPU, so the counters must be summed rather than read from a single line.
const conntrackFixture = `entries  clashes found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error  expect_new expect_create expect_delete search_restart
00000021 00000000 0000000a 00000000 00000019 0007eb1c 00000000 00000000 00000000 00000002 00000010 00000003 00000000  00000000 00000000 00000000 00000006
00000021 00000000 0000000b 00000000 00000019 0007eb1c 00000000 00000000 00000000 00000001 00000020 00000004 00000000  00000000 00000000 00000000 00000006
`

func TestParseConntrackStatsSumsPerCPURows(t *testing.T) {
	got, err := ParseConntrackStats(strings.NewReader(conntrackFixture))
	if err != nil {
		t.Fatal(err)
	}
	// 0x10 + 0x20 = 48, 0x3 + 0x4 = 7, 0x2 + 0x1 = 3.
	if got.Drops != 48 || got.EarlyDrops != 7 || got.InsertFailed != 3 {
		t.Fatalf("got %+v, want drops=48 early=7 insert_failed=3", got)
	}
}

// Kernels have added and removed columns over the years. Reading by position
// would silently attribute one counter's value to another; reading by name
// means an absent column contributes nothing.
func TestParseConntrackStatsToleratesMissingColumns(t *testing.T) {
	minimal := "entries found invalid drop\n00000005 00000002 00000000 0000000f\n"
	got, err := ParseConntrackStats(strings.NewReader(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if got.Drops != 15 {
		t.Fatalf("drops = %d, want 15", got.Drops)
	}
	if got.EarlyDrops != 0 || got.InsertFailed != 0 {
		t.Fatalf("absent columns invented values: %+v", got)
	}
}

func TestParseConntrackStatsRejectsMalformedValue(t *testing.T) {
	if _, err := ParseConntrackStats(strings.NewReader("entries drop\n0001 zzzz\n")); err == nil {
		t.Fatal("expected an error for a non-hex counter")
	}
}

func TestParseConntrackStatsRejectsEmptyFile(t *testing.T) {
	if _, err := ParseConntrackStats(strings.NewReader("")); err == nil {
		t.Fatal("expected an error for a file with no header")
	}
}

func tcpSnapshotWith(at time.Time, reasm, frag uint64, ct *ConntrackStats) TCPSnapshot {
	return TCPSnapshot{
		At:        at,
		SNMP:      ProtocolCounters{"Ip": {"ReasmFails": reasm, "FragFails": frag}, "Tcp": {}, "Udp": {}},
		Conntrack: ct,
	}
}

func TestDeltaReportsIPFragmentationCounters(t *testing.T) {
	start := time.Now()
	first := collect.Data{Snapshot: tcpSnapshotWith(start, 10, 4, nil)}
	last := collect.Data{Snapshot: tcpSnapshotWith(start.Add(time.Second), 17, 9, nil)}
	got, err := TCPCollector{}.Delta(first, last)
	if err != nil {
		t.Fatal(err)
	}
	if got.TCP.IPReassemblyFailures != 7 || got.TCP.IPFragmentationFailures != 5 {
		t.Fatalf("got reasm=%d frag=%d, want 7 and 5", got.TCP.IPReassemblyFailures, got.TCP.IPFragmentationFailures)
	}
}

func TestDeltaReportsConntrackOnlyWithBothBoundaries(t *testing.T) {
	start := time.Now()
	before := &ConntrackStats{Drops: 5, EarlyDrops: 1, InsertFailed: 0}
	after := &ConntrackStats{Drops: 9, EarlyDrops: 1, InsertFailed: 3}

	got, err := TCPCollector{}.Delta(
		collect.Data{Snapshot: tcpSnapshotWith(start, 0, 0, before)},
		collect.Data{Snapshot: tcpSnapshotWith(start.Add(time.Second), 0, 0, after)})
	if err != nil {
		t.Fatal(err)
	}
	if got.Conntrack == nil {
		t.Fatal("no conntrack delta despite both boundaries")
	}
	if got.Conntrack.Drops != 4 || got.Conntrack.EarlyDrops != 0 || got.Conntrack.InsertFailed != 3 {
		t.Fatalf("wrong conntrack delta: %+v", got.Conntrack)
	}

	// Netfilter loaded only partway through the window gives no interval. The
	// honest answer is that nothing was measured, not that nothing was dropped.
	partial, err := TCPCollector{}.Delta(
		collect.Data{Snapshot: tcpSnapshotWith(start, 0, 0, nil)},
		collect.Data{Snapshot: tcpSnapshotWith(start.Add(time.Second), 0, 0, after)})
	if err != nil {
		t.Fatal(err)
	}
	if partial.Conntrack != nil {
		t.Fatalf("conntrack reported without a baseline: %+v", partial.Conntrack)
	}
}
