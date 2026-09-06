package network

import (
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
)

func TestParseDevAndDelta(t *testing.T) {
	input := "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n eth0: 100 2 3 4 0 0 0 0 200 5 6 7 0 0 0 0\n lo: 8 9 0 0 0 0 0 0 8 9 0 0 0 0 0 0\n"
	got, err := ParseDev(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if got["eth0"].TXErrors != 6 || got["eth0"].RXDrop != 4 {
		t.Fatalf("wrong counters: %#v", got["eth0"])
	}
	delta := Delta(got["eth0"], Counters{RXBytes: 150, RXPackets: 3, RXErrors: 4, RXDrop: 1, TXBytes: 220, TXPackets: 8, TXErrors: 6, TXDrop: 9})
	if delta.RXBytes != 50 || delta.RXDrop != 0 || delta.TXDrop != 2 {
		t.Fatalf("wrong delta: %#v", delta)
	}
}

func TestParseDevRejectsMalformed(t *testing.T) {
	if _, err := ParseDev(strings.NewReader("header\nheader\nx: 1 2\n")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestCollectorDeltaSkipsInterfaceWithoutBaseline(t *testing.T) {
	c := Collector{}
	start := time.Now()
	first := collect.Data{Snapshot: Snapshot{At: start, Interfaces: []Interface{{Name: "eth0", Counters: Counters{RXErrors: 4}}}}}
	last := collect.Data{Snapshot: Snapshot{At: start.Add(time.Second), Interfaces: []Interface{
		{Name: "eth0", Counters: Counters{RXErrors: 5}},
		{Name: "veth-new", Counters: Counters{RXErrors: 99, TXErrors: 99}},
	}}}
	got, err := c.Delta(first, last)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Network) != 1 || got.Network[0].Name != "eth0" || got.Network[0].RXErrors != 1 {
		t.Fatalf("network delta=%#v, want only sampled eth0 delta", got.Network)
	}
}
