package icmpcheck

import (
	"context"
	"errors"
	"testing"
)

const pingOutput = `PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=64 time=1.20 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=64 time=1.40 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 2 received, 33.3% packet loss, time 2003ms
rtt min/avg/max/mdev = 1.200/1.300/1.400/0.100 ms
`

func TestCollectReportsPacketLoss(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			return []byte(pingOutput), errors.New("exit status 1")
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	check := data.ICMPCheck
	if check == nil || !check.Available || check.Target != "1.1.1.1" {
		t.Fatalf("unexpected check: %+v", check)
	}
	if check.Sent != 3 || check.Received != 2 {
		t.Fatalf("sent/received = %d/%d, want 3/2", check.Sent, check.Received)
	}
	if check.AvgLatencyMillis != 1.3 {
		t.Fatalf("avg latency = %v, want 1.3", check.AvgLatencyMillis)
	}
}

func TestCollectReportsUnavailableWhenPingMissing(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "", errors.New("executable file not found in $PATH") },
		run: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("run should not be called when ping is missing")
			return nil, nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.ICMPCheck != nil {
		t.Fatalf("expected no check when ping is missing, got %+v", data.ICMPCheck)
	}
	if len(data.Diagnostics) != 1 || data.Diagnostics[0].Status != "unavailable" {
		t.Fatalf("expected an unavailable diagnostic, got %+v", data.Diagnostics)
	}
}

func TestNameIsICMPCheck(t *testing.T) {
	if (&Collector{}).Name() != "icmp-check" {
		t.Fatalf("unexpected name: %s", (&Collector{}).Name())
	}
}
