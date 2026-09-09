// Package gatewayping actively probes the default gateway with ICMP echo
// requests. Unlike the passive route table networkstate reads, this sends
// real packets on the local network segment, so it only runs as part of the
// active-check profile (on by default, --disable-external-checks turns it
// off).
//
// It shells out to the system `ping` binary rather than opening a raw or
// unprivileged ICMP socket itself. On essentially every Linux distribution
// `ping` already carries CAP_NET_RAW (or is setuid root) from the package
// manager, so it works regardless of the current user's ping_group_range,
// unlike a socket this process opens itself. This mirrors how every other
// optional integration in this tool works: a bounded, timed-out external
// command that reports itself unavailable when missing, never a fault.
package gatewayping

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
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
	routePath = "/proc/net/route"
	// rtfGateway is the route flag bit (RTF_GATEWAY) marking a route that goes
	// through a gateway rather than being directly connected.
	rtfGateway = 0x2
	// rtfUp marks a route the kernel may use. A gateway route without it is
	// present in procfs but must not be selected for an active probe.
	rtfUp = 0x1

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

func (c *Collector) Name() string { return "gateway-ping" }

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

	raw, err := readFile(routePath)
	if err != nil {
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "route table: " + err.Error()}}}, nil
	}
	gateway := defaultGateway(string(raw))
	if gateway == "" {
		// No default gateway is a legitimate, intentionally isolated setup;
		// network-no-default-route in backlog.go already covers it as a fact.
		// There is nothing here for this probe to test.
		return collect.Data{}, nil
	}

	path, lookErr := lookPath("ping")
	if lookErr != nil {
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "ping: " + lookErr.Error()}}}, nil
	}

	ctx, cancel := context.WithTimeout(parent, commandTimeout)
	defer cancel()
	sent, received, avgMillis, pingErr := pingutil.Run(ctx, run, path, "-c", strconv.Itoa(pingCount), "-W", strconv.Itoa(perPingTimeout), gateway)
	if parent.Err() != nil {
		return collect.Data{}, parent.Err()
	}
	if pingErr != nil {
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "ping: " + pingErr.Error()}}}, nil
	}

	check := &model.GatewayCheck{Available: true, Gateway: gateway, Sent: sent, Received: received, AvgLatencyMillis: avgMillis}
	if sent > 0 {
		check.PacketLossPct = float64(sent-received) * 100 / float64(sent)
	}
	return collect.Data{GatewayCheck: check}, nil
}

// defaultGateway reads the main IPv4 route table directly instead of shelling
// out to `ip route`, so this collector needs no extra command beyond `ping`
// itself and does not depend on collection ordering with networkstate. This is
// deliberately a conservative main-table fallback, not a claim about policy
// routing: only usable all-zero destination/mask routes qualify, and the
// lowest metric wins. Equal metrics retain their procfs order, which is a
// deterministic fallback when the kernel's policy selection is unavailable.
func defaultGateway(raw string) string {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Scan() // header line
	var bestMetric uint64
	bestGateway := ""
	bestSet := false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		destination, gatewayHex, flagsHex, metricText, mask := fields[1], fields[2], fields[3], fields[6], fields[7]
		flags, err := strconv.ParseUint(flagsHex, 16, 16)
		metric, metricErr := strconv.ParseUint(metricText, 10, 64)
		if err != nil || metricErr != nil || destination != "00000000" || mask != "00000000" || flags&(rtfUp|rtfGateway) != (rtfUp|rtfGateway) {
			continue
		}
		if ip, err := hexToIPv4(gatewayHex); err == nil && ip != "0.0.0.0" && (!bestSet || metric < bestMetric) {
			bestMetric = metric
			bestGateway = ip
			bestSet = true
		}
	}
	return bestGateway
}

// hexToIPv4 decodes the little-endian hex address /proc/net/route uses.
func hexToIPv4(hex string) (string, error) {
	value, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return "", err
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(value))
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]), nil
}
