package network

import (
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
)

const devHeader = "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"

// The parser already split all sixteen columns and kept eight. Overruns, frame
// errors, collisions and carrier losses separate a link fault from congestion,
// so they are retained rather than discarded.
func TestParseDevRetainsLinkColumns(t *testing.T) {
	got, err := ParseDev(strings.NewReader(devHeader + " eth0: 100 2 3 4 11 12 0 0 200 5 6 7 13 14 15 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	c := got["eth0"]
	for _, tc := range []struct {
		name string
		got  uint64
		want uint64
	}{
		{"RXFIFO", c.RXFIFO, 11},
		{"RXFrame", c.RXFrame, 12},
		{"TXFIFO", c.TXFIFO, 13},
		{"Collisions", c.Collisions, 14},
		{"TXCarrier", c.TXCarrier, 15},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

func TestDeltaCoversLinkCountersAndClampsResets(t *testing.T) {
	before := Counters{RXFIFO: 10, RXFrame: 10, TXFIFO: 10, TXCarrier: 10, Collisions: 10}
	after := Counters{RXFIFO: 15, RXFrame: 12, TXFIFO: 10, TXCarrier: 1, Collisions: 30}
	d := Delta(before, after)
	if d.RXFIFO != 5 || d.RXFrame != 2 || d.TXFIFO != 0 || d.Collisions != 20 {
		t.Fatalf("wrong link delta: %#v", d)
	}
	// A counter that went backwards means the interface was reset. Reporting
	// the underflow would invent a large fault out of nothing.
	if d.TXCarrier != 0 {
		t.Fatalf("reset counter produced %d, want 0", d.TXCarrier)
	}
}

func linkInterface(name string) Interface {
	carrier, speed := true, uint64(1000)
	return Interface{
		Name: name, OperState: "up", MTU: 9000, Carrier: &carrier, SpeedMbps: &speed, Duplex: "full",
		Counters: Counters{RXPackets: 100, RXFrame: 7, Collisions: 3},
	}
}

// The collector already read these gauges from sysfs and then dropped them at
// the Delta boundary, so nothing downstream could see the link at all.
func TestCollectorDeltaCarriesLinkFacts(t *testing.T) {
	start := time.Now()
	base := linkInterface("eth0")
	base.Counters = Counters{RXPackets: 40, RXFrame: 2, Collisions: 1}
	first := collect.Data{Snapshot: Snapshot{At: start, Interfaces: []Interface{base}}}
	last := collect.Data{Snapshot: Snapshot{At: start.Add(time.Second), Interfaces: []Interface{linkInterface("eth0")}}}
	got, err := Collector{}.Delta(first, last)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Network) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(got.Network))
	}
	n := got.Network[0]
	if n.MTU != 9000 || n.Duplex != "full" {
		t.Errorf("link facts missing: mtu=%d duplex=%q", n.MTU, n.Duplex)
	}
	if n.Carrier == nil || !*n.Carrier {
		t.Errorf("carrier = %v, want true", n.Carrier)
	}
	if n.SpeedMbps == nil || *n.SpeedMbps != 1000 {
		t.Errorf("speed = %v, want 1000", n.SpeedMbps)
	}
	// Gauges are current values; the counters beside them are still deltas.
	if n.RXFrameErrors != 5 || n.Collisions != 2 {
		t.Errorf("counters not sampled: frame=%d collisions=%d", n.RXFrameErrors, n.Collisions)
	}
}

// Without a baseline the interval is unknown, but the link itself is still
// fully described. Dropping the inventory would hide a down port precisely
// when sampling failed.
func TestFinalGaugesKeepLinkFactsWithoutCounters(t *testing.T) {
	last := collect.Data{Snapshot: Snapshot{At: time.Now(), Interfaces: []Interface{linkInterface("eth0")}}}
	got, err := Collector{}.Delta(collect.Data{}, last)
	if err == nil {
		t.Fatal("expected an error reporting the missing baseline")
	}
	if len(got.Network) != 1 {
		t.Fatalf("got %d interfaces, want the final inventory", len(got.Network))
	}
	n := got.Network[0]
	if n.MTU != 9000 || n.SpeedMbps == nil || *n.SpeedMbps != 1000 {
		t.Errorf("link facts lost without a baseline: %+v", n)
	}
	if n.SampleDurationSeconds != 0 || n.RXFrameErrors != 0 || n.Collisions != 0 {
		t.Errorf("unsampled entry reported activity: %+v", n)
	}
}

// The reported metric must not alias the collector's snapshot, or a later
// mutation of the snapshot would silently rewrite an already-reported value.
func TestLinkFactsCopyPointerValues(t *testing.T) {
	iface := linkInterface("eth0")
	entry := linkFacts(iface)
	*iface.Carrier = false
	*iface.SpeedMbps = 10
	if entry.Carrier == nil || !*entry.Carrier {
		t.Error("carrier aliased the snapshot")
	}
	if entry.SpeedMbps == nil || *entry.SpeedMbps != 1000 {
		t.Error("speed aliased the snapshot")
	}
}
