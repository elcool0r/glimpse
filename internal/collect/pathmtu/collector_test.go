package pathmtu

import (
	"context"
	"errors"
	"os/exec"
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

func packetTooBigOutput() []byte {
	return []byte(`PING 1.1.1.1 (1.1.1.1) 1472(1500) bytes of data.
From 192.0.2.1 icmp_seq=1 Frag needed and DF set (mtu = 1400)

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss
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

func TestCollectRecordsLargestReducedDFReply(t *testing.T) {
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
	if check.PacketTooBigFeedback {
		t.Fatalf("summary-only drops must not invent packet-too-big feedback: %+v", check)
	}
}

func TestCollectKeepsPacketTooBigFeedbackSeparateFromEchoReply(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if !containsFlag(args, "-M") {
				return []byte(baselineOKOutput), nil
			}
			if payloadArg(args) <= 1400 {
				return deliveredOutput(), nil
			}
			return packetTooBigOutput(), errors.New("exit status 1")
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	check := data.PathMTUCheck
	if check == nil || check.DiscoveredMTU != 1428 || !check.PacketTooBigFeedback {
		t.Fatalf("feedback and reply observation = %+v", check)
	}
}

func TestPacketTooBigFeedbackRecognitionIsNarrow(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{name: "remote feedback", text: "Frag needed and DF set (mtu = 1400)", want: true},
		{name: "local feedback", text: "ping: local error: Message too long, mtu=1400", want: true},
		{name: "case insensitive", text: "MESSAGE TOO LONG", want: true},
		{name: "timeout", text: "1 packets transmitted, 0 received, 100% packet loss", want: false},
		{name: "exit text", text: "exit status 1", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasPacketTooBigFeedback([]byte(tt.text)); got != tt.want {
				t.Fatalf("hasPacketTooBigFeedback(%q) = %t, want %t", tt.text, got, tt.want)
			}
		})
	}
}

func TestRunCommandCapturesFeedbackFromStderrUnderCLocale(t *testing.T) {
	path, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	output, err := runCommand(context.Background(), path, "-c", `printf 'locale=%s\n' "$LC_ALL"; printf 'Frag needed and DF set\n' >&2`)
	if err != nil {
		t.Fatal(err)
	}
	text := string(output)
	if !strings.Contains(text, "locale=C") || !hasPacketTooBigFeedback(output) {
		t.Fatalf("combined stable-locale output = %q", text)
	}
}

func TestCollectRecordsWhenNoTestedDFSizeReplies(t *testing.T) {
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
		t.Fatalf("expected DiscoveredMTU=0 when no tested DF size replied, got %+v", check)
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
