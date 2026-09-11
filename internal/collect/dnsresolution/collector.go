// Package dnsresolution actively verifies that name resolution works. Unlike
// networkstate's DNS config parser, which only reads /etc/resolv.conf, this
// collector sends real queries to real servers -- one to whatever the host
// has configured as its local nameserver, and one to the external resolver
// at 1.1.1.1. Because that means outbound network contact, including to the
// public internet, it belongs to the active-check profile: like the other
// active checks it is on by default and --disable-external-checks turns the
// whole group off.
package dnsresolution

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/networkstate"
	"github.com/elcool0r/glimpse/internal/model"
)

const (
	queryTimeout   = 3 * time.Second
	externalServer = "1.1.1.1"
	// testDomain is the IANA-reserved example domain: stable, always
	// resolvable, and carries no association with either server being tested.
	testDomain     = "example.com"
	resolvConfPath = "/etc/resolv.conf"
)

type Collector struct {
	readFile func(string) ([]byte, error)
	lookup   func(context.Context, string, string) (time.Duration, error)
}

func New() *Collector {
	return &Collector{readFile: os.ReadFile, lookup: lookupHost}
}

func (c *Collector) Name() string { return "dns-resolution" }

// Static marks this as a gauge: repeating the same two live queries at both
// sampling boundaries would double outbound DNS traffic for no benefit.
func (c *Collector) Static() {}

func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	readFile, lookup := c.readFile, c.lookup
	if readFile == nil {
		readFile = os.ReadFile
	}
	if lookup == nil {
		lookup = lookupHost
	}

	resolution := &model.DNSResolution{Available: true}
	if server := localNameserver(readFile); server != "" {
		resolution.Local = probe(parent, lookup, server, testDomain)
	}
	resolution.External = probe(parent, lookup, externalServer, testDomain)

	return collect.Data{DNSResolution: resolution}, nil
}

// localNameserver reads the first configured nameserver directly rather than
// depending on the networkstate collector's output, so this collector stays
// self-contained and does not need collection ordering between the two.
func localNameserver(readFile func(string) ([]byte, error)) string {
	raw, err := readFile(resolvConfPath)
	if err != nil {
		return ""
	}
	dns := networkstate.ParseResolvConf(string(raw))
	if len(dns.Nameservers) == 0 {
		return ""
	}
	return dns.Nameservers[0]
}

func probe(parent context.Context, lookup func(context.Context, string, string) (time.Duration, error), server, domain string) *model.DNSResolutionResult {
	if parent.Err() != nil {
		return &model.DNSResolutionResult{Server: server, Domain: domain, Error: parent.Err().Error()}
	}
	ctx, cancel := context.WithTimeout(parent, queryTimeout)
	defer cancel()
	result := &model.DNSResolutionResult{Server: server, Domain: domain}
	latency, err := lookup(ctx, server, domain)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Resolved = true
	result.LatencyMillis = float64(latency.Microseconds()) / 1000
	return result
}

// lookupHost queries server directly for domain, bypassing the system
// resolver. That way the local and external checks each test the specific
// server responsible for the answer, rather than both silently going through
// whichever resolver the OS happens to be configured with.
func lookupHost(ctx context.Context, server, domain string) (time.Duration, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, network, net.JoinHostPort(server, "53"))
		},
	}
	start := time.Now()
	_, err := resolver.LookupHost(ctx, domain)
	return time.Since(start), err
}
