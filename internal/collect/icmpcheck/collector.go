// Package icmpcheck actively pings a fixed external anchor host, independent
// of the default gateway that internal/collect/gatewayping already checks.
// A healthy gateway only proves the local link works; it says nothing about
// whether this host can reach anything beyond it (a firewall dropping all
// outbound ICMP, a broken upstream link past the local router). Like the
// other active checks, it sends real packets and only runs in the
// active-check profile (--disable-external-checks turns it off).
package icmpcheck

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
	// target is the same fixed external anchor the other active checks use,
	// so this tool has one external dependency to reason about, not several.
	target         = "1.1.1.1"
	pingCount      = 3
	perPingTimeout = 1 // seconds, passed to `ping -W`
	commandTimeout = 5 * time.Second
)

type Collector struct {
	lookPath func(string) (string, error)
	run      func(context.Context, string, ...string) ([]byte, error)
}

func New() *Collector {
	return &Collector{lookPath: exec.LookPath, run: pingutil.RunCommand}
}

func (c *Collector) Name() string { return "icmp-check" }

// Static marks this as a gauge: the ping series is one bounded probe, not a
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

	ctx, cancel := context.WithTimeout(parent, commandTimeout)
	defer cancel()
	sent, received, avgMillis, pingErr := pingutil.Run(ctx, run, path, "-4", "-c", strconv.Itoa(pingCount), "-W", strconv.Itoa(perPingTimeout), target)
	if parent.Err() != nil {
		return collect.Data{}, parent.Err()
	}
	if pingErr != nil {
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "ping: " + pingErr.Error()}}}, nil
	}

	check := &model.ICMPCheck{Available: true, Target: target, Sent: sent, Received: received, AvgLatencyMillis: avgMillis}
	if sent > 0 {
		check.PacketLossPct = float64(sent-received) * 100 / float64(sent)
	}
	return collect.Data{ICMPCheck: check}, nil
}
