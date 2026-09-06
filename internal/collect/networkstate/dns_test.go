package networkstate

import (
	"context"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func TestParseResolvConf(t *testing.T) {
	raw := `# Managed by systemd-resolved
nameserver 10.0.0.1
nameserver 10.0.0.2  ; secondary
search corp.example.com example.com
domain legacy.example.com
options edns0 trust-ad
notadirective 1.2.3.4
`
	got := ParseResolvConf(raw)
	if !got.Available {
		t.Fatal("available = false")
	}
	if want := []string{"10.0.0.1", "10.0.0.2"}; !reflect.DeepEqual(got.Nameservers, want) {
		t.Errorf("nameservers = %v, want %v", got.Nameservers, want)
	}
	want := []string{"corp.example.com", "example.com", "legacy.example.com"}
	if !reflect.DeepEqual(got.SearchDomains, want) {
		t.Errorf("search domains = %v, want %v", got.SearchDomains, want)
	}
	if got.StubResolver {
		t.Error("real nameservers reported as the stub")
	}
}

func TestParseResolvConfDetectsStub(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"systemd stub", "nameserver 127.0.0.53\n", true},
		{"both stub addresses", "nameserver 127.0.0.53\nnameserver 127.0.0.54\n", true},
		// A local dnsmasq or unbound on 127.0.0.1 is a different arrangement
		// and must not be mistaken for systemd-resolved.
		{"local resolver", "nameserver 127.0.0.1\n", false},
		{"stub plus upstream", "nameserver 127.0.0.53\nnameserver 1.1.1.1\n", false},
		{"empty", "options edns0\n", false},
	} {
		if got := ParseResolvConf(tc.raw).StubResolver; got != tc.want {
			t.Errorf("%s: stub = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestParseResolvConfBoundsUnboundedFile(t *testing.T) {
	raw := ""
	for i := 0; i < 50; i++ {
		raw += "nameserver 10.0.0.1\nsearch a.example b.example\n"
	}
	got := ParseResolvConf(raw)
	if len(got.Nameservers) > maxNameservers || len(got.SearchDomains) > maxSearchDomains {
		t.Fatalf("unbounded parse: %d nameservers, %d domains", len(got.Nameservers), len(got.SearchDomains))
	}
}

// A minimal container has no iproute2 at all. Losing the resolver report along
// with the socket inventory would hide a fault that a plain file read can see.
func TestCollectReportsDNSWithoutIproute2(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "", exec.ErrNotFound },
		readFile: func(path string) ([]byte, error) {
			if path == resolvConfPath {
				return []byte("nameserver 1.1.1.1\n"), nil
			}
			return nil, os.ErrNotExist
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.NetworkState == nil || got.NetworkState.DNS == nil {
		t.Fatalf("no DNS reported without ss: %+v", got.NetworkState)
	}
	if len(got.NetworkState.DNS.Nameservers) != 1 {
		t.Errorf("nameservers = %v", got.NetworkState.DNS.Nameservers)
	}
	// The absent commands are still reported as gaps rather than passed over.
	if len(got.Diagnostics) == 0 {
		t.Error("missing ss produced no diagnostic")
	}
}

func TestCollectReportsUnreadableResolvConf(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "", exec.ErrNotFound },
		readFile: func(string) ([]byte, error) { return nil, os.ErrPermission },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.NetworkState != nil {
		t.Fatalf("state reported with nothing collected: %+v", got.NetworkState)
	}
	var sawResolv bool
	for _, d := range got.Diagnostics {
		if len(d.Detail) >= 12 && d.Detail[:12] == "resolv.conf:" {
			sawResolv = true
		}
	}
	if !sawResolv {
		t.Fatalf("unreadable resolv.conf produced no diagnostic: %+v", got.Diagnostics)
	}
}
