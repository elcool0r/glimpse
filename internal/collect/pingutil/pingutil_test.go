package pingutil

import (
	"context"
	"errors"
	"testing"
)

const iputilsOutput = `PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.20 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=1.40 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 2 received, 33.3% packet loss, time 2003ms
rtt min/avg/max/mdev = 1.200/1.300/1.400/0.100 ms
`

const busyboxOutput = `PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: seq=0 ttl=64 time=1.200 ms
64 bytes from 192.168.1.1: seq=1 ttl=64 time=1.400 ms
64 bytes from 192.168.1.1: seq=2 ttl=64 time=1.300 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 1.200/1.300/1.400 ms
`

// macOS ping's round-trip line adds a stddev field iputils and BusyBox do
// not have; the parser must not depend on the field count after "=".
const macOSOutput = `PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=1.200 ms
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.400 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=1.300 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 1.200/1.300/1.400/0.100 ms
`

func TestParseOutputIputils(t *testing.T) {
	sent, received, avg, err := ParseOutput(iputilsOutput)
	if err != nil {
		t.Fatalf("ParseOutput returned error: %v", err)
	}
	if sent != 3 || received != 2 {
		t.Fatalf("sent/received = %d/%d, want 3/2", sent, received)
	}
	if avg != 1.300 {
		t.Fatalf("avg = %v, want 1.300", avg)
	}
}

func TestParseOutputBusyBox(t *testing.T) {
	sent, received, avg, err := ParseOutput(busyboxOutput)
	if err != nil {
		t.Fatalf("ParseOutput returned error: %v", err)
	}
	if sent != 3 || received != 3 {
		t.Fatalf("sent/received = %d/%d, want 3/3", sent, received)
	}
	if avg != 1.300 {
		t.Fatalf("avg = %v, want 1.300", avg)
	}
}

func TestParseOutputMacOS(t *testing.T) {
	sent, received, avg, err := ParseOutput(macOSOutput)
	if err != nil {
		t.Fatalf("ParseOutput returned error: %v", err)
	}
	if sent != 3 || received != 3 {
		t.Fatalf("sent/received = %d/%d, want 3/3", sent, received)
	}
	if avg != 1.300 {
		t.Fatalf("avg = %v, want 1.300", avg)
	}
}

func TestParseOutputMissingSummaryIsAnError(t *testing.T) {
	if _, _, _, err := ParseOutput("ping: sendto: Network is unreachable\n"); err == nil {
		t.Fatal("expected an error when the summary line is missing")
	}
}

func TestRunTrustsOutputOverNonzeroExit(t *testing.T) {
	run := func(context.Context, string, ...string) ([]byte, error) {
		return []byte(iputilsOutput), errors.New("exit status 1")
	}
	sent, received, avg, err := Run(context.Background(), run, "/bin/ping", "-c", "3")
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if sent != 3 || received != 2 || avg != 1.3 {
		t.Fatalf("sent/received/avg = %d/%d/%v, want 3/2/1.3", sent, received, avg)
	}
}

func TestRunFailsWhenOutputIsUnparseable(t *testing.T) {
	run := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ping: sendto: Network is unreachable\n"), errors.New("exit status 2")
	}
	if _, _, _, err := Run(context.Background(), run, "/bin/ping"); err == nil {
		t.Fatal("expected an error when neither output nor exit status yields a result")
	}
}
