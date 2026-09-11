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

// Collect performs the full observation. It is the BoundaryFinal behaviour;
// callers that go through the sampling lifecycle reach CollectAt instead.
func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	return c.CollectAt(parent, collect.BoundaryFinal)
}

// CollectAt skips the `--failed` query at the baseline boundary and ignores
// the timestamp properties there. Delta reads only NRestarts from the first
// observation; everything else the baseline gathers is discarded by merge.
func (c *Collector) CollectAt(parent context.Context, boundary collect.Boundary) (collect.Data, error) {
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

	full := boundary == collect.BoundaryFinal
	var failedUnits []string
	if full {
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
		failedUnits = ParseFailedUnits(string(failedOutput))
	}

	var diagnostics []model.CollectionStatus
	restarts := map[string]uint64{}
	failedSince := map[string]time.Time{}
	var recentStarts []model.SystemdUnitStart
	serviceUnitsDiscovered, serviceUnitsInspected := 0, 0
	serviceUnitScanLimited := false
	listCtx, cancel := context.WithTimeout(parent, timeout)
	listOutput, listErr := run(listCtx, path, "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	cancel()
	switch {
	case listErr != nil && parent.Err() != nil:
		return collect.Data{}, parent.Err()
	case listErr != nil && !full:
		// At the baseline boundary the restart counters are this collector's
		// only output that survives merge, and list-units is how the units to
		// query are discovered. Reporting the same unavailable shape the final
		// boundary reports for `--failed` keeps a dead bus from producing two
		// differently-worded diagnostics for one cause.
		return collect.Data{Systemd: &model.Systemd{Available: false}, Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: listErr.Error()}}}, nil
	case listErr != nil:
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "list-units: " + listErr.Error()})
	default:
		names := parseUnitNames(string(listOutput))
		// Failed units are normally included in list-units, but append any
		// missing names so failed non-service units can also receive their
		// StateChangeTimestamp.
		known := make(map[string]struct{}, len(names))
		for _, name := range names {
			known[name] = struct{}{}
		}
		for _, unit := range failedUnits {
			if _, ok := known[unit]; !ok {
				names = append(names, unit)
				known[unit] = struct{}{}
			}
		}
		serviceUnitsDiscovered = len(names)
		if len(names) > maxUnits {
			serviceUnitScanLimited = true
			names = names[:maxUnits]
		}
		serviceUnitsInspected = len(names)
		if len(names) > 0 {
			args := append([]string{"show"}, names...)
			args = append(args, "--property=Id,NRestarts,ActiveEnterTimestamp,StateChangeTimestamp", "--no-pager")
			showCtx, cancel := context.WithTimeout(parent, timeout)
			showOutput, showErr := run(showCtx, path, args...)
			cancel()
			switch {
			case showErr != nil && parent.Err() != nil:
				return collect.Data{}, parent.Err()
			case showErr != nil:
				diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "show: " + showErr.Error()})
			default:
				showText := string(showOutput)
				restarts = parseRestarts(showText)
				if full {
					recentStarts = recentUnitStarts(parseActiveEnterTimestamps(showText), time.Now())
					failedSince = parseUnitTimestamps(showText, "StateChangeTimestamp")
				}
			}
		}
	}

	return collect.Data{
		Systemd: &model.Systemd{
			Available: true, FailedUnits: failedUnits, FailedUnitSince: failedSince, RecentStarts: recentStarts,
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
	return parseUnitTimestamps(output, "ActiveEnterTimestamp")
}

func parseUnitTimestamps(output, property string) map[string]time.Time {
	result := make(map[string]time.Time)
	for _, block := range showBlocks(output) {
		id, value := block["Id"], block[property]
		if id == "" || value == "" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) < 3 {
			continue
		}
		if t, err := time.ParseInLocation(activeEnterLayout, strings.Join(fields[:3], " "), time.Local); err == nil {
			result[id] = t
		}
	}
	return result
}

// showBlocks splits `systemctl show <units...>` output into one key/value map
// per unit. systemd separates units with a blank line but does not promise
// any particular order for the properties within a block, and the previous
// line-at-a-time readers required Id to arrive before the property they were
// looking for: had systemd ever emitted NRestarts first, restart detection
// would have returned an empty result on every run, with no error and no
// diagnostic to show for it. Assembling the block first makes the position of
// Id genuinely irrelevant, which is what the comments already claimed.
func showBlocks(output string) []map[string]string {
	var blocks []map[string]string
	current := map[string]string{}
	flush := func() {
		if len(current) > 0 {
			blocks = append(blocks, current)
			current = map[string]string{}
		}
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok {
			current[key] = value
		}
	}
	flush()
	return blocks
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	result, err := command.Run(ctx, command.Options{MaxOutput: maxOutput}, name, args...)
	return result.Output, err
}

// ParseFailedUnits parses the stable first column of `systemctl --failed`
// output. Decorative headings and an empty result are ignored.
//
// The columns are UNIT, LOAD, ACTIVE, SUB, DESCRIPTION. Filtering on LOAD ==
// "loaded" silently dropped genuinely failed units: a unit whose file was
// removed or made invalid while it was failed reports LOAD=not-found (or
// bad-setting) alongside ACTIVE=failed, and those are exactly the ones worth
// surfacing. `--no-legend --plain` already removes the header and the status
// bullet, and requiring a dot in the unit name rejects anything else, so the
// LOAD column is not needed as a guard. ACTIVE is checked instead, which is
// the state `--failed` actually selects on.
func ParseFailedUnits(output string) []string {
	units := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.Contains(fields[0], ".") {
			continue
		}
		if fields[2] != "failed" {
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
// output: one block of "Key=Value" lines per unit, separated by a blank line.
// The block is assembled before either key is read, so the order systemd
// happens to emit properties in cannot affect the result.
func parseRestarts(output string) map[string]uint64 {
	restarts := make(map[string]uint64)
	for _, block := range showBlocks(output) {
		id := block["Id"]
		if id == "" {
			continue
		}
		if n, err := strconv.ParseUint(block["NRestarts"], 10, 64); err == nil {
			restarts[id] = n
		}
	}
	return restarts
}
