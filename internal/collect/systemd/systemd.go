// Package systemd collects failed unit names and per-unit restart counts
// through systemctl when it is available. It is intentionally optional:
// containers and non-systemd hosts commonly do not expose a usable system
// bus.
package systemd

import (
	"context"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/command"
	"github.com/elcool0r/glimpse/internal/model"
)

const (
	commandTimeout = 3 * time.Second
	maxOutput      = 256 << 10
	// maxUnits bounds the restart-count query to a reasonable number of
	// services; this is a health snapshot, not an exhaustive inventory.
	maxUnits = 512
)

// Collector collects current failed systemd units and, across the sampling
// window, which units' restart counters increased. Timeout is configurable
// for tests; a zero value uses the conservative default.
type Collector struct {
	Timeout  time.Duration
	lookPath func(string) (string, error)
	run      func(context.Context, string, ...string) ([]byte, error)
}

func New() *Collector {
	return &Collector{lookPath: exec.LookPath, run: runCommand}
}

func (c *Collector) Name() string { return "systemd" }

// snapshot carries each unit's raw, cumulative NRestarts between the two
// collection boundaries so Delta can compute how many happened during the
// sample -- the cumulative value alone would flag any unit that has ever
// restarted since boot as perpetually suspicious.
type snapshot struct{ restarts map[string]uint64 }

func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	lookup := c.lookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	path, err := lookup("systemctl")
	if err != nil {
		return collect.Data{Systemd: &model.Systemd{Available: false}, Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: err.Error()}}}, nil
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = commandTimeout
	}
	run := c.run
	if run == nil {
		run = runCommand
	}

	failedCtx, cancel := context.WithTimeout(parent, timeout)
	failedOutput, failedErr := run(failedCtx, path, "--failed", "--no-legend", "--plain", "--no-pager")
	cancel()
	// A disconnected user/container bus is an unavailable capability, not a
	// health error. Context cancellation remains meaningful to the caller.
	if failedErr != nil {
		if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		}
		return collect.Data{Systemd: &model.Systemd{Available: false}, Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: failedErr.Error()}}}, nil
	}

	var diagnostics []model.CollectionStatus
	restarts := map[string]uint64{}
	var recentStarts []model.SystemdUnitStart
	serviceUnitsDiscovered, serviceUnitsInspected := 0, 0
	serviceUnitScanLimited := false
	listCtx, cancel := context.WithTimeout(parent, timeout)
	listOutput, listErr := run(listCtx, path, "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	cancel()
	switch {
	case listErr != nil && parent.Err() != nil:
		return collect.Data{}, parent.Err()
	case listErr != nil:
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "list-units: " + listErr.Error()})
	default:
		names := parseUnitNames(string(listOutput))
		serviceUnitsDiscovered = len(names)
		if len(names) > maxUnits {
			serviceUnitScanLimited = true
			names = names[:maxUnits]
		}
		serviceUnitsInspected = len(names)
		if len(names) > 0 {
			args := append([]string{"show"}, names...)
			args = append(args, "--property=Id,NRestarts,ActiveEnterTimestamp", "--no-pager")
			showCtx, cancel := context.WithTimeout(parent, timeout)
			showOutput, showErr := run(showCtx, path, args...)
			cancel()
			switch {
			case showErr != nil && parent.Err() != nil:
				return collect.Data{}, parent.Err()
			case showErr != nil:
				diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "show: " + showErr.Error()})
			default:
				restarts = parseRestarts(string(showOutput))
				recentStarts = recentUnitStarts(parseActiveEnterTimestamps(string(showOutput)), time.Now())
			}
		}
	}

	return collect.Data{
		Systemd: &model.Systemd{
			Available: true, FailedUnits: ParseFailedUnits(string(failedOutput)), RecentStarts: recentStarts,
			ServiceUnitsDiscovered: serviceUnitsDiscovered, ServiceUnitsInspected: serviceUnitsInspected,
			ServiceUnitScanLimited: serviceUnitScanLimited,
		},
		Snapshot:    snapshot{restarts: restarts},
		Diagnostics: diagnostics,
	}, nil
}

// recentUnitStartsWindow bounds RecentStarts to a reasonable lookback --
// most units on a host last started at boot, days or weeks ago, and are not
// interesting; this matches the kernel log scanner's own 24h bound.
const recentUnitStartsWindow = 24 * time.Hour

// recentUnitStarts filters to units that entered the active state within the
// lookback window, discarding anything older (or, defensively, timestamps
// that appear to be in the future -- a clock step during collection).
func recentUnitStarts(activeEnter map[string]time.Time, now time.Time) []model.SystemdUnitStart {
	var starts []model.SystemdUnitStart
	for unit, at := range activeEnter {
		if at.After(now) || now.Sub(at) > recentUnitStartsWindow {
			continue
		}
		starts = append(starts, model.SystemdUnitStart{Unit: unit, At: at})
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i].At.After(starts[j].At) })
	return starts
}

// Delta compares each unit's restart counter between the two boundaries.
// A unit missing from the baseline (created during the window) has no
// interval to report and is left alone; a counter that went backwards
// (systemd was reloaded, resetting its tracked state) is not a clean delta
// and is also left alone rather than reported as a negative or wrapped
// count.
func (c *Collector) Delta(first, last collect.Data) (collect.Data, error) {
	if last.Systemd == nil {
		return last, nil
	}
	a, aok := first.Snapshot.(snapshot)
	b, bok := last.Snapshot.(snapshot)
	if !aok || !bok {
		return last, nil
	}
	var restarting []model.SystemdUnitRestart
	for unit, after := range b.restarts {
		before, ok := a.restarts[unit]
		if !ok || after < before {
			continue
		}
		if delta := after - before; delta > 0 {
			restarting = append(restarting, model.SystemdUnitRestart{Unit: unit, RestartsDelta: delta})
		}
	}
	sort.Slice(restarting, func(i, j int) bool {
		if restarting[i].RestartsDelta != restarting[j].RestartsDelta {
			return restarting[i].RestartsDelta > restarting[j].RestartsDelta
		}
		return restarting[i].Unit < restarting[j].Unit
	})
	last.Systemd.RestartingUnits = restarting
	return last, nil
}

// activeEnterLayout matches systemctl show's timestamp format for a property
// like ActiveEnterTimestamp, e.g. "Sat 2024-01-06 08:12:45 UTC". Only the
// first three fields (weekday, date, time) are parsed; the trailing zone
// abbreviation is ignored and the numeric fields are parsed in the local
// zone instead, since Go cannot reliably resolve an arbitrary zone
// abbreviation as printed, but systemd already formats these in the host's
// local time -- the same zone glimpse's own process uses.
const activeEnterLayout = "Mon 2006-01-02 15:04:05"

// parseActiveEnterTimestamps reads `systemctl show <units...>
// --property=Id,...,ActiveEnterTimestamp` output the same way parseRestarts
// does. A unit that has never been active reports an empty value, which is
// skipped rather than treated as an error.
func parseActiveEnterTimestamps(output string) map[string]time.Time {
	result := make(map[string]time.Time)
	var currentID string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			currentID = ""
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "Id":
			currentID = value
		case "ActiveEnterTimestamp":
			if currentID == "" || value == "" {
				continue
			}
			fields := strings.Fields(value)
			if len(fields) < 3 {
				continue
			}
			if t, err := time.ParseInLocation(activeEnterLayout, strings.Join(fields[:3], " "), time.Local); err == nil {
				result[currentID] = t
			}
		}
	}
	return result
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	result, err := command.Run(ctx, command.Options{MaxOutput: maxOutput}, name, args...)
	return result.Output, err
}

// ParseFailedUnits parses the stable first column of `systemctl --failed`
// output. Decorative headings and an empty result are ignored.
func ParseFailedUnits(output string) []string {
	units := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.Contains(fields[0], ".") {
			continue
		}
		if fields[1] != "loaded" {
			continue
		}
		if _, exists := seen[fields[0]]; exists {
			continue
		}
		seen[fields[0]] = struct{}{}
		units = append(units, fields[0])
	}
	sort.Strings(units)
	return units
}

// parseUnitNames reads the stable first column of `systemctl list-units`.
func parseUnitNames(output string) []string {
	names := make([]string, 0)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		names = append(names, fields[0])
	}
	return names
}

// parseRestarts reads `systemctl show <units...> --property=Id,NRestarts`
// output: one block of "Key=Value" lines per unit, separated by a blank
// line. Parsing by key rather than relying on the property order keeps this
// resilient to systemd emitting properties in a different order.
func parseRestarts(output string) map[string]uint64 {
	restarts := make(map[string]uint64)
	var currentID string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			currentID = ""
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "Id":
			currentID = value
		case "NRestarts":
			if currentID == "" {
				continue
			}
			if n, err := strconv.ParseUint(value, 10, 64); err == nil {
				restarts[currentID] = n
			}
		}
	}
	return restarts
}
