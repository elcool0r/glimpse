package network

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
)

func TestParseProtocolCounters(t *testing.T) {
	input := "Tcp: RtoAlgorithm RtoMin CurrEstab InSegs OutSegs RetransSegs\nTcp: 1 200 4 10 20 3\nUdp: InDatagrams InErrors\nUdp: 8 2\n"
	got, err := ParseProtocolCounters(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if got["Tcp"]["CurrEstab"] != 4 || got["Tcp"]["RetransSegs"] != 3 || got["Udp"]["InErrors"] != 2 {
		t.Fatalf("unexpected counters: %#v", got)
	}
}

func TestParseProtocolCountersRejectsUnpairedLines(t *testing.T) {
	if _, err := ParseProtocolCounters(strings.NewReader("Tcp: InSegs\nUdp: 1\n")); err == nil {
		t.Fatal("expected protocol mismatch error")
	}
}

func TestParseSockStat(t *testing.T) {
	got, err := ParseSockStat(strings.NewReader("sockets: used 42\nTCP: inuse 5 orphan 1 tw 9 alloc 12 mem 3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got["TCP"]["tw"] != 9 || got["sockets"]["used"] != 42 {
		t.Fatalf("unexpected sockstat: %#v", got)
	}
}

func TestTCPCollectorDelta(t *testing.T) {
	first := TCPSnapshot{At: time.Unix(10, 0), SNMP: ProtocolCounters{"Tcp": {"InSegs": 10, "OutSegs": 20, "RetransSegs": 2, "ActiveOpens": 1, "PassiveOpens": 3, "AttemptFails": 2, "EstabResets": 1}, "Udp": {"InErrors": 5}}, NetStat: ProtocolCounters{"TcpExt": {"ListenOverflows": 1, "ListenDrops": 2}}}
	last := TCPSnapshot{At: time.Unix(12, 0), SNMP: ProtocolCounters{"Tcp": {"InSegs": 13, "OutSegs": 24, "RetransSegs": 4, "ActiveOpens": 5, "PassiveOpens": 7, "AttemptFails": 3, "EstabResets": 2, "CurrEstab": 6}, "Udp": {"InErrors": 8}}, NetStat: ProtocolCounters{"TcpExt": {"ListenOverflows": 2, "ListenDrops": 4}}, SockStat: SocketStats{"TCP": {"tw": 12, "orphan": 2}}}
	data, err := (TCPCollector{}).Delta(collect.Data{Snapshot: first}, collect.Data{Snapshot: last})
	if err != nil {
		t.Fatal(err)
	}
	if data.TCP.Sampled == nil || !*data.TCP.Sampled || data.TCP.RetransmittedSegments != 2 || data.TCP.ListenDrops != 2 || data.TCP.UDPInErrors != 3 || data.TCP.CurrentEstablished != 6 || data.TCP.TimeWaitSockets != 12 {
		t.Fatalf("unexpected TCP delta: %#v", data.TCP)
	}
}

func TestTCPCollectorDeltaRejectsInvalidSamplingInterval(t *testing.T) {
	first := TCPSnapshot{At: time.Unix(10, 0)}
	last := TCPSnapshot{At: time.Unix(10, 0), SNMP: ProtocolCounters{"Tcp": {"CurrEstab": 7}}}
	data, err := (TCPCollector{}).Delta(collect.Data{Snapshot: first}, collect.Data{Snapshot: last})
	if err == nil || data.TCP == nil || data.TCP.Sampled == nil || *data.TCP.Sampled || data.TCP.CurrentEstablished != 7 {
		t.Fatalf("invalid interval was reported as sampled: data=%#v err=%v", data, err)
	}
}

func TestTCPCollectorDeltaWithoutBaselineKeepsSocketGaugesMarkedUnsampled(t *testing.T) {
	last := TCPSnapshot{SNMP: ProtocolCounters{"Tcp": {"CurrEstab": 7}}, SockStat: SocketStats{"TCP": {"tw": 9, "orphan": 2}}}
	data, err := (TCPCollector{}).Delta(collect.Data{}, collect.Data{Snapshot: last})
	if err == nil {
		t.Fatal("expected missing baseline error")
	}
	if data.TCP == nil || data.TCP.Sampled == nil || *data.TCP.Sampled || data.TCP.CurrentEstablished != 7 || data.TCP.TimeWaitSockets != 9 || data.TCP.OrphanSockets != 2 {
		t.Fatalf("final socket gauges were not retained as unsampled: %#v", data.TCP)
	}
	encoded, err := json.Marshal(data.TCP)
	if err != nil || !strings.Contains(string(encoded), `"sampled":false`) {
		t.Fatalf("unsampled TCP JSON = %s, err = %v", encoded, err)
	}
}
