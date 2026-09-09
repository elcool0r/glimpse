package network

import (
	"encoding/json"
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

func TestCollectorDeltaKeepsInterfaceWithoutBaselineAsUnsampled(t *testing.T) {
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
	if len(got.Network) != 2 || got.Network[0].Sampled == nil || !*got.Network[0].Sampled || got.Network[0].Name != "eth0" || got.Network[0].RXErrors != 1 || got.Network[1].Sampled == nil || *got.Network[1].Sampled || got.Network[1].Name != "veth-new" {
		t.Fatalf("network delta=%#v, want sampled eth0 and final-only veth-new", got.Network)
	}
}

func TestCollectorDeltaRejectsInvalidSamplingInterval(t *testing.T) {
	for _, lastAt := range []time.Time{time.Time{}, time.Unix(10, 0)} {
		first := Snapshot{At: time.Unix(10, 0), Interfaces: []Interface{{Name: "eth0"}}}
		last := Snapshot{At: lastAt, Interfaces: []Interface{{Name: "eth0"}}}
		data, err := (Collector{}).Delta(collect.Data{Snapshot: first}, collect.Data{Snapshot: last})
		if err == nil || len(data.Network) != 1 || data.Network[0].Sampled == nil || *data.Network[0].Sampled {
			t.Fatalf("lastAt=%v: invalid interval was reported as sampled: data=%#v err=%v", lastAt, data, err)
		}
	}
}

func TestCollectorDeltaWithoutBaselineKeepsFinalLinkFactsMarkedUnsampled(t *testing.T) {
	carrier := true
	last := Snapshot{Interfaces: []Interface{{Name: "eth0", OperState: "up", MTU: 1500, Carrier: &carrier}}}
	data, err := (Collector{}).Delta(collect.Data{}, collect.Data{Snapshot: last})
	if err == nil {
		t.Fatal("expected missing baseline error")
	}
	if len(data.Network) != 1 || data.Network[0].Sampled == nil || *data.Network[0].Sampled || data.Network[0].Name != "eth0" || data.Network[0].MTU != 1500 || data.Network[0].Carrier == nil || !*data.Network[0].Carrier {
		t.Fatalf("final link facts were not retained as unsampled: %#v", data.Network)
	}
	encoded, err := json.Marshal(data.Network[0])
	if err != nil || !strings.Contains(string(encoded), `"sampled":false`) {
		t.Fatalf("unsampled network JSON = %s, err = %v", encoded, err)
	}
}
