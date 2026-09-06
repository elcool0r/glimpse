// Package ipv6check actively pings a fixed external IPv6 anchor host, but
// only when this host has a global-scope IPv6 address configured at all. An
// IPv4-only host is not a fault -- disabling IPv6 is a deliberate, common
// choice -- so this check is skipped entirely rather than warned about, the
// same treatment a missing default route gets. When a host does have global
// IPv6 configured and this fails anyway (egress filtering, a broken
// upstream IPv6 path), that is a real fault none of the IPv4 checks can see.
//
// Like the other active checks, it sends real packets and only runs in the
// active-check profile (--disable-external-checks turns it off).
package ipv6check

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/pingutil"
	"github.com/elcool0r/glimpse/internal/model"
)

const (
	if6Path = "/proc/net/if_inet6"
	// target is Cloudflare's IPv6 anchor, the IPv6 counterpart of the 1.1.1.1
	// anchor the other active checks use.
	target         = "2606:4700:4700::1111"
	pingCount      = 3
	perPingTimeout = 1 // seconds, passed to `ping -W`
	commandTimeout = 5 * time.Second
)

type Collector struct {
	readFile func(string) ([]byte, error)
	lookPath func(string) (string, error)
	run      func(context.Context, string, ...string) ([]byte, error)
}

func New() *Collector {
	return &Collector{readFile: os.ReadFile, lookPath: exec.LookPath, run: pingutil.RunCommand}
}

func (c *Collector) Name() string { return "ipv6-check" }

// Static marks this as a gauge: the ping series is one bounded probe, not a
// sampled counter needing two boundaries.
func (c *Collector) Static() {}

func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	readFile, lookPath, run := c.readFile, c.lookPath, c.run
	if readFile == nil {
		readFile = os.ReadFile
	}
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	if run == nil {
		run = pingutil.RunCommand
	}

	raw, err := readFile(if6Path)
	if err != nil {
		// No IPv6 stack exposed via procfs at all; nothing to test.
		return collect.Data{}, nil
	}
	if !hasGlobalAddress(string(raw)) {
		// IPv4-only is a deliberate, common configuration, not a fault.
		return collect.Data{}, nil
	}

	path, lookErr := lookPath("ping")
	if lookErr != nil {
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "ping: " + lookErr.Error()}}}, nil
	}

	ctx, cancel := context.WithTimeout(parent, commandTimeout)
	defer cancel()
	sent, received, avgMillis, pingErr := pingutil.Run(ctx, run, path, "-6", "-c", strconv.Itoa(pingCount), "-W", strconv.Itoa(perPingTimeout), target)
	if parent.Err() != nil {
		return collect.Data{}, parent.Err()
	}
	if pingErr != nil {
		// Covers both a genuine ping failure and a `ping` build without IPv6
		// support (no -6 flag): either way, this cannot be judged, not
		// treated as a fault.
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "ping -6: " + pingErr.Error()}}}, nil
	}

	check := &model.IPv6Check{Available: true, Target: target, Sent: sent, Received: received, AvgLatencyMillis: avgMillis}
	if sent > 0 {
		check.PacketLossPct = float64(sent-received) * 100 / float64(sent)
	}
	return collect.Data{IPv6Check: check}, nil
}

// hasGlobalAddress reports whether /proc/net/if_inet6 lists any address with
// global scope (kernel scope value 0x00) that is not the unspecified or
// loopback address. Link-local (fe80::/10, scope 0x20) addresses exist on
// essentially every interface regardless of whether the host has any real
// IPv6 connectivity, so they do not count.
func hasGlobalAddress(raw string) bool {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		address, scopeHex := fields[0], fields[3]
		scope, err := strconv.ParseUint(scopeHex, 16, 8)
		if err != nil || scope != 0 {
			continue
		}
		if address == strings.Repeat("0", 32) || address == strings.Repeat("0", 31)+"1" {
			continue // unspecified :: or loopback ::1
		}
		return true
	}
	return false
}
