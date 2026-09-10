package packageupdates

import (
	"context"
	"errors"
	"testing"
)

func TestParseAPTCountsInstLines(t *testing.T) {
	out := "Reading package lists...\nInst linux-firmware [1] (2)\nInst docker-ce [1] (2)\nConf docker-ce (2)\n"
	if got := ParseAPT(out); got != 2 {
		t.Fatalf("got %d updates, want 2", got)
	}
}

func TestParseRPMTableCountsPackagesOnly(t *testing.T) {
	out := "Last metadata expiration check: 0:01:00 ago\nPackage Arch Version Repository\nopenssl x86_64 3.0.1 baseos\n7 packages marked for upgrade\n"
	if got := ParseDNF(out); got != 1 {
		t.Fatalf("got %d updates, want 1", got)
	}
}

func TestCollectAcceptsDNFExit100WithUpdates(t *testing.T) {
	c := Collector{
		lookPath: func(name string) (string, error) {
			if name == "dnf" {
				return "/usr/bin/dnf", nil
			}
			return "", errors.New("missing")
		},
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("Package Arch Version Repository\nopenssl x86_64 3.0.1 baseos\n"), errors.New("exit status 100")
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil || data.PackageUpdates == nil || data.PackageUpdates.Count != 1 {
		t.Fatalf("unexpected result: data=%+v err=%v", data, err)
	}
}

func TestCollectDoesNotTreatMissingManagerAsError(t *testing.T) {
	c := Collector{lookPath: func(string) (string, error) { return "", errors.New("missing") }, run: nil}
	data, err := c.Collect(context.Background())
	if err != nil || data.PackageUpdates != nil || len(data.Diagnostics) != 0 {
		t.Fatalf("unexpected result: data=%+v err=%v", data, err)
	}
}
