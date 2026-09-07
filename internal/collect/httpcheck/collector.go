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
	"net/url"
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

type Collector struct {
	get   func(ctx context.Context, url string) (status int, latency time.Duration, err error)
	proxy func(*http.Request) (*url.URL, error)
}

// New honors HTTP_PROXY, HTTPS_PROXY, and NO_PROXY by default. Passing true
// disables proxy discovery for this collector only, preserving direct IPv4
// probing for users who explicitly request --no-proxy.
func New(disableProxy ...bool) *Collector {
	proxy := http.ProxyFromEnvironment
	if len(disableProxy) > 0 && disableProxy[0] {
		proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	}
	return &Collector{proxy: proxy}
}

func (c *Collector) Name() string { return "http-check" }

// Static marks this as a gauge: two bounded one-shot requests, not a sampled
// counter needing two boundaries.
func (c *Collector) Static() {}

func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	get := c.get
	if get == nil {
		get = c.doGet
	}
	check := &model.HTTPCheck{Available: true}
	check.HTTP = probe(parent, get, "http://"+target+"/")
	check.HTTP.ProxyUsed = c.proxyUsed(parent, check.HTTP.URL)
	if parent.Err() != nil {
		return collect.Data{}, parent.Err()
	}
	check.HTTPS = probe(parent, get, "https://"+target+"/")
	check.HTTPS.ProxyUsed = c.proxyUsed(parent, check.HTTPS.URL)
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
func (c *Collector) doGet(ctx context.Context, url string) (int, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "glimpse-health-check/1")
	proxyURL, err := c.proxyFor(req)
	if err != nil {
		return 0, 0, err
	}
	start := time.Now()
	client := directClient()
	if proxyURL != nil {
		client = proxyClient(c.proxyFor)
	}
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		return 0, latency, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, latency, nil
}

func (c *Collector) proxyUsed(ctx context.Context, rawURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	proxyURL, err := c.proxyFor(req)
	return err == nil && proxyURL != nil
}

func (c *Collector) proxyFor(req *http.Request) (*url.URL, error) {
	if c.proxy == nil {
		return http.ProxyFromEnvironment(req)
	}
	return c.proxy(req)
}

// directClient forces IPv4 only for direct probes. A proxy may legitimately
// be IPv6-only, so proxied connections retain the transport's normal dialing.
func directClient() *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", addr)
	}}}
}

func proxyClient(proxy func(*http.Request) (*url.URL, error)) *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: proxy}}
}
