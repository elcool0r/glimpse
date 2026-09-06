package pathmtu

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
)

const baselineOKOutput = `PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=64 time=10.0 ms

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 10.0/10.0/10.0 ms
`

const baselineUnreachableOutput = `PING 1.1.1.1 (1.1.1.1): 56 data bytes

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss
`

func droppedOutput() []byte {
	return []byte(`PING 1.1.1.1 (1.1.1.1): 1472 data bytes

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss
`)
}

func deliveredOutput() []byte {
	return []byte(`PING 1.1.1.1 (1.1.1.1): 1472 data bytes
1480 bytes from 1.1.1.1: icmp_seq=0 ttl=64 time=12.0 ms

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 12.0/12.0/12.0 ms
`)
}

// payloadArg extracts the -s argument (the payload size) from a ping
// invocation's arguments, or -1 if there isn't one.
func payloadArg(args []string) int {
	for i, arg := range args {
		if arg == "-s" && i+1 < len(args) {
			v, _ := strconv.Atoi(args[i+1])
			return v
		}
	}
	return -1
}

func TestCollectFullMTUWorks(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if !containsFlag(args, "-M") {
				return []byte(baselineOKOutput), nil
			}
			return deliveredOutput(), nil // the first (largest) candidate succeeds
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	check := data.PathMTUCheck
	if check == nil || !check.Available || !check.BaselineOK {
		t.Fatalf("expected an available, baseline-OK check, got %+v", check)
	}
	if check.DiscoveredMTU != check.CeilingMTU {
		t.Fatalf("discovered = %d, want full ceiling %d", check.DiscoveredMTU, check.CeilingMTU)
	}
}

func TestCollectDiscoversReducedMTU(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if !containsFlag(args, "-M") {
				return []byte(baselineOKOutput), nil
			}
			// Only the 1400-byte payload (and smaller) makes it through.
			if payloadArg(args) <= 1400 {
				return deliveredOutput(), nil
			}
			return droppedOutput(), errors.New("exit status 1")
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	check := data.PathMTUCheck
	if check == nil {
		t.Fatal("expected a check result")
	}
	if check.DiscoveredMTU != 1400+28 {
		t.Fatalf("discovered = %d, want %d", check.DiscoveredMTU, 1400+28)
	}
	if check.DiscoveredMTU >= check.CeilingMTU {
		t.Fatalf("expected a reduced MTU below the ceiling, got %d/%d", check.DiscoveredMTU, check.CeilingMTU)
	}
}

func TestCollectNoUsableSizeIsBlackhole(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if !containsFlag(args, "-M") {
				return []byte(baselineOKOutput), nil
			}
			return droppedOutput(), errors.New("exit status 1")
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	check := data.PathMTUCheck
	if check == nil || check.DiscoveredMTU != 0 {
		t.Fatalf("expected DiscoveredMTU=0 (black hole) when nothing gets through, got %+v", check)
	}
	if !check.BaselineOK {
		t.Fatalf("baseline should still be OK: %+v", check)
	}
}

func TestCollectSkipsWhenAnchorUnreachable(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(baselineUnreachableOutput), errors.New("exit status 1")
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.PathMTUCheck != nil {
		t.Fatalf("expected no check when the anchor is unreachable, got %+v", data.PathMTUCheck)
	}
	if len(data.Diagnostics) != 0 {
		t.Fatalf("an unreachable anchor is not this probe's own failure, want no diagnostics, got %+v", data.Diagnostics)
	}
}

func TestCollectUnsupportedFlagIsUnavailableNotBlackhole(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if containsFlag(args, "-M") {
				return []byte("ping: invalid option -- 'M'\n"), errors.New("exit status 2")
			}
			return []byte(baselineOKOutput), nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.PathMTUCheck != nil {
		t.Fatalf("an unsupported ping flag must not be reported as a black hole, got %+v", data.PathMTUCheck)
	}
	if len(data.Diagnostics) != 1 || data.Diagnostics[0].Status != "unavailable" {
		t.Fatalf("expected an unavailable diagnostic, got %+v", data.Diagnostics)
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
	if len(data.Diagnostics) != 1 || data.Diagnostics[0].Status != "unavailable" {
		t.Fatalf("expected an unavailable diagnostic, got %+v", data.Diagnostics)
	}
}

func TestNameIsPathMTU(t *testing.T) {
	if (&Collector{}).Name() != "path-mtu" {
		t.Fatalf("unexpected name: %s", (&Collector{}).Name())
	}
}

func containsFlag(args []string, flag string) bool {
	for _, arg := range args {
		if strings.EqualFold(arg, flag) {
			return true
		}
	}
	return false
}
