package dnsresolution

import (
	"context"
	"errors"
	"testing"
	"time"
)

func fakeReadFile(content string, err error) func(string) ([]byte, error) {
	return func(string) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		return []byte(content), nil
	}
}

func TestCollectProbesLocalAndExternal(t *testing.T) {
	c := &Collector{
		readFile: fakeReadFile("nameserver 192.0.2.53\n", nil),
		lookup: func(_ context.Context, server, domain string) (time.Duration, error) {
			if server == "192.0.2.53" {
				return 5 * time.Millisecond, nil
			}
			if server == externalServer {
				return 10 * time.Millisecond, nil
			}
			t.Fatalf("unexpected server %q", server)
			return 0, nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	res := data.DNSResolution
	if res == nil || !res.Available {
		t.Fatalf("resolution not available: %+v", res)
	}
	if res.Local == nil || !res.Local.Resolved || res.Local.Server != "192.0.2.53" {
		t.Fatalf("local result wrong: %+v", res.Local)
	}
	if res.External == nil || !res.External.Resolved || res.External.Server != externalServer {
		t.Fatalf("external result wrong: %+v", res.External)
	}
	if res.Local.Domain != testDomain || res.External.Domain != testDomain {
		t.Fatalf("domain mismatch: local=%q external=%q", res.Local.Domain, res.External.Domain)
	}
}

func TestCollectSkipsLocalWhenNoNameserverConfigured(t *testing.T) {
	c := &Collector{
		readFile: fakeReadFile("", errors.New("no such file")),
		lookup: func(_ context.Context, server, domain string) (time.Duration, error) {
			return time.Millisecond, nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.DNSResolution.Local != nil {
		t.Fatalf("expected no local probe without a configured nameserver, got %+v", data.DNSResolution.Local)
	}
	if data.DNSResolution.External == nil || !data.DNSResolution.External.Resolved {
		t.Fatalf("external probe should still run: %+v", data.DNSResolution.External)
	}
}

func TestCollectRecordsFailures(t *testing.T) {
	c := &Collector{
		readFile: fakeReadFile("nameserver 192.0.2.53\n", nil),
		lookup: func(_ context.Context, server, domain string) (time.Duration, error) {
			return 0, errors.New("no route to host")
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.DNSResolution.Local.Resolved || data.DNSResolution.Local.Error == "" {
		t.Fatalf("expected a recorded local failure: %+v", data.DNSResolution.Local)
	}
	if data.DNSResolution.External.Resolved || data.DNSResolution.External.Error == "" {
		t.Fatalf("expected a recorded external failure: %+v", data.DNSResolution.External)
	}
}

func TestNameIsDNSResolution(t *testing.T) {
	if (&Collector{}).Name() != "dns-resolution" {
		t.Fatalf("unexpected name: %s", (&Collector{}).Name())
	}
}
