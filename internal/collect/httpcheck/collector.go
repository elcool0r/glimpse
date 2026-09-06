// Package httpcheck actively fetches a fixed external URL over plain HTTP
// and over HTTPS, testing outbound web connectivity beyond what DNS
// resolution and an ICMP ping can show -- a host can resolve names and ping
// its gateway while port 80/443 egress is filtered, proxied, or otherwise
// broken. Like the other active checks, it sends real requests to a real
// external server and only runs in the active-check profile
// (--disable-external-checks turns it off).
package httpcheck

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

const (
	// target is the IANA-reserved example domain: stable, always resolvable,
	// serves both plain HTTP and HTTPS, and carries no tracking or vendor
	// association.
	target  = "example.com"
	timeout = 5 * time.Second
)

// client forces IPv4 connections. Without this, a dual-stack host that
// blocks only IPv4 egress (the common way to test this with plain iptables,
// which does not touch IPv6 at all) would silently succeed over IPv6
// instead, hiding exactly the fault this check exists to catch. IPv6
// reachability has its own dedicated check (internal/collect/ipv6check).
var client = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", addr)
		},
	},
}

type Collector struct {
	get func(ctx context.Context, url string) (status int, latency time.Duration, err error)
}

func New() *Collector {
	return &Collector{get: doGet}
}

func (c *Collector) Name() string { return "http-check" }

// Static marks this as a gauge: two bounded one-shot requests, not a sampled
// counter needing two boundaries.
func (c *Collector) Static() {}

func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	get := c.get
	if get == nil {
		get = doGet
	}
	check := &model.HTTPCheck{Available: true}
	check.HTTP = probe(parent, get, "http://"+target+"/")
	if parent.Err() != nil {
		return collect.Data{}, parent.Err()
	}
	check.HTTPS = probe(parent, get, "https://"+target+"/")
	if parent.Err() != nil {
		return collect.Data{}, parent.Err()
	}
	return collect.Data{HTTPCheck: check}, nil
}

func probe(parent context.Context, get func(context.Context, string) (int, time.Duration, error), url string) *model.HTTPCheckResult {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	result := &model.HTTPCheckResult{URL: url}
	status, latency, err := get(ctx, url)
	result.StatusCode = status
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Succeeded = true
	result.LatencyMillis = float64(latency.Microseconds()) / 1000
	return result
}

// doGet performs one GET. Success means a complete HTTP response was
// received, whatever its status code -- this tests reachability, not
// whether the target's own content is correct.
func doGet(ctx context.Context, url string) (int, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "glimpse-health-check/1")
	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		return 0, latency, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, latency, nil
}
