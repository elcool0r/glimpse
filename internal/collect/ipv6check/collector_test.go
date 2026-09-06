package ipv6check

import (
	"context"
	"errors"
	"testing"
)

const if6WithGlobal = "20010db8000000000000000000000001 03 40 00 80       eth0\n" +
	"fe800000000000000000000000000001 03 40 20 80       eth0\n"

const if6LinkLocalOnly = "fe800000000000000000000000000001 03 40 20 80       eth0\n" +
	"00000000000000000000000000000001 01 80 10 80       lo\n"

const pingOutput = `PING 2606:4700:4700::1111 (2606:4700:4700::1111) 56 data bytes
64 bytes from 2606:4700:4700::1111: icmp_seq=1 ttl=64 time=5.20 ms
64 bytes from 2606:4700:4700::1111: icmp_seq=2 ttl=64 time=5.40 ms
64 bytes from 2606:4700:4700::1111: icmp_seq=3 ttl=64 time=5.30 ms

--- 2606:4700:4700::1111 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 5.200/5.300/5.400/0.100 ms
`

func fakeReadFile(content string, err error) func(string) ([]byte, error) {
	return func(string) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		return []byte(content), nil
	}
}

func TestHasGlobalAddress(t *testing.T) {
	if !hasGlobalAddress(if6WithGlobal) {
		t.Fatal("expected a global address to be detected")
	}
	if hasGlobalAddress(if6LinkLocalOnly) {
		t.Fatal("link-local and loopback addresses must not count as global")
	}
}

func TestCollectSkipsWithoutGlobalAddress(t *testing.T) {
	c := &Collector{
		readFile: fakeReadFile(if6LinkLocalOnly, nil),
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("ping should not run on an IPv4-only host")
			return nil, nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.IPv6Check != nil {
		t.Fatalf("expected no check without a global IPv6 address, got %+v", data.IPv6Check)
	}
}

func TestCollectSkipsWithoutIPv6Stack(t *testing.T) {
	c := &Collector{
		readFile: fakeReadFile("", errors.New("no such file or directory")),
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("ping should not run without an IPv6 stack")
			return nil, nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.IPv6Check != nil {
		t.Fatalf("expected no check without an IPv6 stack, got %+v", data.IPv6Check)
	}
}

func TestCollectPingsWhenGlobalAddressPresent(t *testing.T) {
	c := &Collector{
		readFile: fakeReadFile(if6WithGlobal, nil),
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			return []byte(pingOutput), nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	check := data.IPv6Check
	if check == nil || !check.Available {
		t.Fatalf("expected an available check, got %+v", check)
	}
	if check.Sent != 3 || check.Received != 3 {
		t.Fatalf("sent/received = %d/%d, want 3/3", check.Sent, check.Received)
	}
}

func TestCollectUnsupportedFlagIsUnavailable(t *testing.T) {
	c := &Collector{
		readFile: fakeReadFile(if6WithGlobal, nil),
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("ping: invalid option -- '6'\n"), errors.New("exit status 2")
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.IPv6Check != nil {
		t.Fatalf("expected no check when ping lacks IPv6 support, got %+v", data.IPv6Check)
	}
	if len(data.Diagnostics) != 1 || data.Diagnostics[0].Status != "unavailable" {
		t.Fatalf("expected an unavailable diagnostic, got %+v", data.Diagnostics)
	}
}

func TestNameIsIPv6Check(t *testing.T) {
	if (&Collector{}).Name() != "ipv6-check" {
		t.Fatalf("unexpected name: %s", (&Collector{}).Name())
	}
}
