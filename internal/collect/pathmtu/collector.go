// Package pathmtu discovers the actual usable path MTU to a fixed external
// anchor host, rather than only testing a single size. A single pass/fail
// probe at 1500 bytes cannot tell a genuine black hole apart from a merely
// reduced but correctly discovered path MTU -- which is normal and healthy
// with PPPoE, VPNs, and tunnels as long as path MTU discovery (PMTUD) is
// working. This collector sends a baseline ping, then a descending series of
// non-fragmentable ("don't fragment") pings, and reports the largest size
// that got through. No usable size at all, despite the baseline succeeding,
// is the actual black-hole signal: PMTUD depends on ICMP "fragmentation
// needed" messages reaching the sender, and when those are filtered, every
// oversized non-fragmentable packet is dropped silently instead of being
// answered with a smaller MTU.
//
// This targets a fixed external host rather than the default gateway that
// internal/collect/gatewayping already checks, because the fault this looks
// for typically happens beyond the local link: a VPN/tunnel whose effective
// MTU the interface's own MTU value does not reflect, or a misconfigured
// middlebox further along the path.
//
// Like the other active checks, it sends real packets and only runs in the
// active-check profile (--disable-external-checks turns it off).
package pathmtu

import (
	"context"
	"os/exec"
	"strconv"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/pingutil"
	"github.com/elcool0r/glimpse/internal/model"
)

const (
	// target is the same fixed external anchor internal/collect/dnsresolution
	// uses for its external DNS probe, so this tool has one external
	// dependency to reason about, not several.
	target = "1.1.1.1"
	// ceilingMTU is the standard Ethernet MTU and the ceiling this probe
	// tests down from; a host with a larger link MTU throughout would still
	// be reported against this common baseline.
	ceilingMTU     = 1500
	perPingTimeout = 1 // seconds, passed to `ping -W`
	commandTimeout = 3 * time.Second
)

// candidatePayloads are ICMP payload sizes to test with the don't-fragment
// bit set, descending from the classic 1472 bytes (1472 + 20-byte IPv4
// header + 8-byte ICMP header = 1500 bytes on the wire) down to 548 (576
// bytes on the wire, the conservative floor most paths are expected to
// carry unfragmented). The search stops at the first success, so a healthy
// full-MTU path costs exactly one extra probe beyond the baseline.
var candidatePayloads = []int{1472, 1464, 1452, 1440, 1420, 1400, 1380, 1360, 1300, 1200, 1000, 800, 600, 548}

type Collector struct {
	lookPath func(string) (string, error)
	run      func(context.Context, string, ...string) ([]byte, error)
}

func New() *Collector {
	return &Collector{lookPath: exec.LookPath, run: pingutil.RunCommand}
}

func (c *Collector) Name() string { return "path-mtu" }

// Static marks this as a gauge: a bounded series of one-shot probes, not a
// sampled counter needing two boundaries.
func (c *Collector) Static() {}

func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	lookPath, run := c.lookPath, c.run
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	if run == nil {
		run = pingutil.RunCommand
	}

	path, lookErr := lookPath("ping")
	if lookErr != nil {
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "ping: " + lookErr.Error()}}}, nil
	}

	if _, received, _, err := pingOnce(parent, run, path, "-c", "1", "-W", strconv.Itoa(perPingTimeout), target); err != nil {
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "path mtu baseline: " + err.Error()}}}, nil
	} else if parent.Err() != nil {
		return collect.Data{}, parent.Err()
	} else if received == 0 {
		// The anchor host is not reachable at all right now, which is a
		// connectivity question the gateway and DNS checks already cover --
		// not evidence about MTU specifically.
		return collect.Data{}, nil
	}

	discovered := 0
	for _, payload := range candidatePayloads {
		// -M do sets the don't-fragment bit: the defining property of this
		// probe. Where the local ping binary does not support it (some
		// BusyBox builds), the very first attempt fails to parse and this
		// reports the whole check unavailable rather than treating a tool
		// incompatibility as a black hole -- a genuine drop still produces a
		// normal summary line, just with zero packets received.
		_, received, _, err := pingOnce(parent, run, path, "-M", "do", "-s", strconv.Itoa(payload), "-c", "1", "-W", strconv.Itoa(perPingTimeout), target)
		if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		}
		if err != nil {
			return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "path mtu probe: " + err.Error()}}}, nil
		}
		if received > 0 {
			discovered = payload + 28
			break
		}
	}

	check := &model.PathMTUCheck{
		Available:  true,
		Target:     target,
		CeilingMTU: ceilingMTU,
		FloorMTU:   candidatePayloads[len(candidatePayloads)-1] + 28,
		BaselineOK: true,
		// DiscoveredMTU stays 0 when nothing in the descending series got
		// through at all -- the black-hole case, not merely a reduced but
		// discoverable path MTU.
		DiscoveredMTU: discovered,
	}
	return collect.Data{PathMTUCheck: check}, nil
}

func pingOnce(parent context.Context, run func(context.Context, string, ...string) ([]byte, error), path string, args ...string) (sent, received int, avgMillis float64, err error) {
	ctx, cancel := context.WithTimeout(parent, commandTimeout)
	defer cancel()
	return pingutil.Run(ctx, run, path, args...)
}
