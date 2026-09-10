// Package app coordinates collection, analysis, and rendering.
package app

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
	"github.com/elcool0r/glimpse/internal/platform"
)

// DefaultBoundaryTimeout bounds one collection boundary. Baseline and final
// collection each receive this budget in full; they are not drawn from a
// single shared allowance, because an overrun at one boundary must not make
// the other boundary — or the sampling window — impossible to complete.
const DefaultBoundaryTimeout = 30 * time.Second

// DefaultObservationTimeout bounds one intermediate trend observation. The
// effective timeout is also capped by the remaining sample window.
const DefaultObservationTimeout = time.Second

type Config struct {
	Duration       time.Duration
	SampleInterval time.Duration
	// BoundaryTimeout bounds optional command work at each collection
	// boundary. A zero value uses DefaultBoundaryTimeout.
	BoundaryTimeout time.Duration
	// ObservationTimeout bounds each intermediate trend observation. A zero
	// value uses DefaultObservationTimeout.
	ObservationTimeout time.Duration
	// Progress receives lifecycle updates synchronously from the coordinating
	// goroutine. Callers that emit machine-readable output should leave it nil.
	Progress func(Progress)
	// Full and IncludeContainers describe the requested collection profile.
	// Collector construction remains at the CLI boundary so optional runtime
	// integrations are never required by the sampling lifecycle.
	Full              bool
	IncludeContainers bool
}

// Progress describes a collection lifecycle transition. It deliberately
// exposes no collector data so reporting progress cannot leak partial facts or
// make the JSON contract timing-dependent.
type Progress struct {
	Phase      string
	Elapsed    time.Duration
	Duration   time.Duration
	Collectors int
}

// Run samples registered collectors at the two window boundaries. It is
// deliberately transport-free so CLI and future APIs share the same lifecycle.
func Run(ctx context.Context, config Config, collectors []collect.Collector) model.Report {
	if config.Duration < 0 {
		config.Duration = 0
	}
	boundary := config.BoundaryTimeout
	if boundary <= 0 {
		boundary = DefaultBoundaryTimeout
	}
	observation := config.ObservationTimeout
	if observation <= 0 {
		observation = DefaultObservationTimeout
	}
	started := time.Now()
	emitProgress(config, Progress{Phase: "baseline", Duration: config.Duration, Collectors: len(collectors)})
	// Static collectors expose gauges, not counter boundaries; merge only reads
	// their final observation, so collecting them here would be pure cost.
	excluded := make([]bool, len(collectors))
	first, firstStatus := collectBoundary(ctx, collectors, boundary, skipStatic, excluded)
	samplingStarted := time.Now()
	sampleDeadline := samplingStarted.Add(config.Duration)
	intermediate, sampledStatus := sampleTrends(ctx, config, collectors, samplingStarted, sampleDeadline, observation, excluded)
	emitProgress(config, Progress{Phase: "final", Elapsed: time.Since(started), Duration: config.Duration, Collectors: len(collectors)})
	last, lastStatus := collectBoundary(ctx, collectors, boundary, collectEvery, excluded)
	samplingEnded := time.Now()
	metrics, deltaStatus := merge(collectors, first, last, excluded)
	metrics.Trends = buildTrends(collectors, append(append([][]collect.Data{first}, intermediate...), last), excluded)
	statuses := append(firstStatus, sampledStatus...)
	statuses = append(statuses, lastStatus...)
	statuses = append(statuses, deltaStatus...)
	// Only an interrupted or cancelled run invalidates the report. A boundary
	// that ran out of its own budget is partial coverage: the collectors that
	// did finish are still reported, and the ones that did not appear in
	// Collection as unavailable.
	if ctx.Err() != nil {
		statuses = append(statuses, model.CollectionStatus{Collector: "sampling", Status: "error", Detail: ctx.Err().Error()})
	}
	statuses = compactStatuses(statuses)
	report := model.Report{
		SchemaVersion: model.SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		// Counter deltas start at the baseline boundary, not when application
		// setup began. In particular, optional collectors can make baseline
		// collection expensive, and including that cost would overstate the
		// interval used to derive sampled metrics.
		SampleDurationSeconds: samplingEnded.Sub(samplingStarted).Seconds(),
		Host:                  platform.Host(), Metrics: metrics, Findings: make([]model.Finding, 0), Collection: statuses,
	}
	// runtime.NumCPU may reflect the process's affinity or cpuset. CPU's
	// count is derived from the same host-wide procfs population used for load
	// and utilization, so it is the only valid normalizer for those signals.
	if metrics.CPU != nil && metrics.CPU.HostCPUCount > 0 {
		report.Host.CPUCount = metrics.CPU.HostCPUCount
	}
	report.Score = model.Score{Value: 100, Status: model.SeverityOK, Label: "EXCELLENT"}
	emitProgress(config, Progress{Phase: "complete", Elapsed: time.Since(started), Duration: config.Duration, Collectors: len(collectors)})
	return report
}

// boundaryMode selects which collectors run at a collection boundary.
type boundaryMode int

const (
	collectEvery boundaryMode = iota
	skipStatic
)

// collectBoundary runs one boundary under its own budget so a slow optional
// integration cannot consume the time the rest of the report needs.
func collectBoundary(parent context.Context, collectors []collect.Collector, budget time.Duration, mode boundaryMode, excluded []bool) ([]collect.Data, []model.CollectionStatus) {
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	data, status, unfinished := collectAll(ctx, collectors, mode, excluded)
	excludeUnfinished(excluded, unfinished)
	return data, status
}

// staticCollector reports whether a collector's baseline observation is
// unused. A collector that also derives deltas is never static, whatever it
// declares, because merge needs both of its observations.
func staticCollector(collector collect.Collector) bool {
	if _, delta := collector.(collect.DeltaCollector); delta {
		return false
	}
	_, static := collector.(collect.StaticCollector)
	return static
}

func emitProgress(config Config, progress Progress) {
	if config.Progress != nil {
		config.Progress(progress)
	}
}

func sampleTrends(ctx context.Context, config Config, collectors []collect.Collector, started, sampleDeadline time.Time, observationTimeout time.Duration, excluded []bool) ([][]collect.Data, []model.CollectionStatus) {
	if config.Duration <= 0 {
		return nil, nil
	}
	emitProgress(config, Progress{Phase: "sampling", Duration: config.Duration, Collectors: len(collectors)})
	hasTrendCollector := false
	for _, collector := range collectors {
		if _, ok := collector.(collect.TrendCollector); ok {
			hasTrendCollector = true
			break
		}
	}
	if !hasTrendCollector || config.SampleInterval <= 0 {
		interval := config.SampleInterval
		if interval <= 0 {
			interval = time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		deadline := time.NewTimer(time.Until(sampleDeadline))
		defer deadline.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil, nil
			case <-deadline.C:
				return nil, nil
			case <-ticker.C:
				elapsed := time.Since(started)
				if elapsed > config.Duration {
					elapsed = config.Duration
				}
				emitProgress(config, Progress{Phase: "sampling", Elapsed: elapsed, Duration: config.Duration, Collectors: len(collectors)})
			}
		}
	}
	interval := config.SampleInterval
	// Long user-selected windows retain at most 600 intermediate snapshots.
	if minimum := config.Duration / 600; interval < minimum {
		interval = minimum
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	deadline := time.NewTimer(time.Until(sampleDeadline))
	defer deadline.Stop()
	var samples [][]collect.Data
	var statuses []model.CollectionStatus
	for {
		select {
		case <-ctx.Done():
			return samples, statuses
		case <-deadline.C:
			return samples, statuses
		case <-ticker.C:
			now := time.Now()
			if !now.Before(sampleDeadline) {
				return samples, statuses
			}
			elapsed := now.Sub(started)
			if elapsed > config.Duration {
				elapsed = config.Duration
			}
			emitProgress(config, Progress{Phase: "sampling", Elapsed: elapsed, Duration: config.Duration, Collectors: len(collectors)})
			observationDeadline := now.Add(observationTimeout)
			if sampleDeadline.Before(observationDeadline) {
				observationDeadline = sampleDeadline
			}
			observationCtx, cancel := context.WithDeadline(ctx, observationDeadline)
			data, status, unfinished := collectTrendAll(observationCtx, collectors, excluded)
			cancel()
			excludeUnfinished(excluded, unfinished)
			samples = append(samples, data)
			statuses = append(statuses, status...)
		}
	}
}

// collectTrendAll retains the registered collector index, while avoiding
// needless repeated reads or optional command execution for static checks.
func collectTrendAll(ctx context.Context, collectors []collect.Collector, excluded []bool) ([]collect.Data, []model.CollectionStatus, []bool) {
	data := make([]collect.Data, len(collectors))
	status := make([]model.CollectionStatus, len(collectors))
	selected := make([]bool, len(collectors))
	for i, collector := range collectors {
		if excluded[i] {
			continue
		}
		if _, ok := collector.(collect.TrendCollector); !ok {
			continue
		}
		selected[i] = true
	}
	results := make(chan collectionResult, countSelected(selected))
	launched := make([]bool, len(collectors))
	running := make([]bool, len(collectors))
	remaining := 0
	for i, collector := range collectors {
		if !selected[i] {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		launched[i] = true
		running[i] = true
		remaining++
		go func(i int, collector collect.Collector) {
			data, err := collector.Collect(ctx)
			results <- collectionResult{index: i, data: data, err: err, finished: time.Now()}
		}(i, collector)
	}
	data, status, unfinished := awaitCollection(ctx, collectors, data, status, running, remaining, results)
	result := status[:0]
	for i := range collectors {
		if launched[i] {
			result = append(result, status[i])
		}
	}
	return data, result, unfinished
}

func buildTrends(collectors []collect.Collector, samples [][]collect.Data, excluded []bool) []model.Trend {
	var trends []model.Trend
	for index, collector := range collectors {
		if excluded[index] {
			continue
		}
		trendCollector, ok := collector.(collect.TrendCollector)
		if !ok {
			continue
		}
		collectorSamples := make([]collect.Data, 0, len(samples))
		for _, sample := range samples {
			if index < len(sample) {
				collectorSamples = append(collectorSamples, sample[index])
			}
		}
		trends = append(trends, trendCollector.Trends(collectorSamples)...)
	}
	return trends
}

func collectAll(ctx context.Context, collectors []collect.Collector, mode boundaryMode, excluded []bool) ([]collect.Data, []model.CollectionStatus, []bool) {
	data := make([]collect.Data, len(collectors))
	status := make([]model.CollectionStatus, len(collectors))
	if ctx.Err() != nil {
		return data, nil, make([]bool, len(collectors))
	}
	selected := make([]bool, len(collectors))
	for i, collector := range collectors {
		if excluded[i] {
			continue
		}
		if mode == skipStatic && staticCollector(collector) {
			continue
		}
		selected[i] = true
	}
	results := make(chan collectionResult, countSelected(selected))
	launched := make([]bool, len(collectors))
	running := make([]bool, len(collectors))
	remaining := 0
	for i, collector := range collectors {
		if !selected[i] {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		launched[i] = true
		running[i] = true
		remaining++
		go func(i int, collector collect.Collector) {
			data, err := collector.Collect(ctx)
			results <- collectionResult{index: i, data: data, err: err, finished: time.Now()}
		}(i, collector)
	}
	data, status, unfinished := awaitCollection(ctx, collectors, data, status, running, remaining, results)
	result := status[:0]
	for i, s := range status {
		if launched[i] {
			result = append(result, s)
		}
	}
	return data, result, unfinished
}

func countSelected(selected []bool) int {
	count := 0
	for _, include := range selected {
		if include {
			count++
		}
	}
	return count
}

func excludeUnfinished(excluded, unfinished []bool) {
	for i, active := range unfinished {
		if active {
			excluded[i] = true
		}
	}
}

// collectionResult is deliberately passed through a buffered channel. A
// collector that ignores cancellation must not keep the coordinator waiting,
// and it must be able to finish later without writing into the returned data.
type collectionResult struct {
	index    int
	data     collect.Data
	err      error
	finished time.Time
}

func awaitCollection(ctx context.Context, collectors []collect.Collector, data []collect.Data, status []model.CollectionStatus, running []bool, remaining int, results <-chan collectionResult) ([]collect.Data, []model.CollectionStatus, []bool) {
	timely := func(result collectionResult) bool {
		deadline, ok := ctx.Deadline()
		return !ok || result.finished.Before(deadline)
	}
	apply := func(result collectionResult) {
		if !running[result.index] {
			return
		}
		data[result.index] = result.data
		status[result.index] = collectionStatus(collectors[result.index].Name(), result.data, result.err)
		running[result.index] = false
		remaining--
	}
	for remaining > 0 {
		select {
		case result := <-results:
			if timely(result) {
				apply(result)
			}
		case <-ctx.Done():
			// Preserve results that raced with cancellation, then report every
			// still-running collector as partial coverage. Never wait for a
			// non-cooperative collector or let it modify the returned slices.
			for {
				select {
				case result := <-results:
					if timely(result) {
						apply(result)
					}
				default:
					for i, active := range running {
						if active {
							status[i] = model.CollectionStatus{Collector: collectors[i].Name(), Status: "error", Detail: ctx.Err().Error()}
						}
					}
					return data, status, running
				}
			}
		}
	}
	return data, status, running
}

func merge(collectors []collect.Collector, first, last []collect.Data, excluded []bool) (model.Metrics, []model.CollectionStatus) {
	var statuses []model.CollectionStatus
	var metrics model.Metrics
	for i, data := range last {
		if sampler, ok := collectors[i].(collect.DeltaCollector); ok && !excluded[i] {
			delta, err := sampler.Delta(first[i], data)
			if err != nil {
				statuses = append(statuses, model.CollectionStatus{Collector: collectors[i].Name(), Status: "error", Detail: fmt.Sprintf("derive sampled metrics: %v", err)})
			}
			// The delta result is authoritative even on error: implementations
			// return the final gauges themselves, marked unsampled, so this
			// cannot fall back to raw boundary counters that nothing has
			// flagged as underived — those would render as a real zero.
			data = delta
		}
		apply(&metrics, data)
	}
	return metrics, statuses
}

func apply(metrics *model.Metrics, data collect.Data) {
	if data.CPU != nil {
		metrics.CPU = data.CPU
	}
	if data.Memory != nil {
		metrics.Memory = data.Memory
	}
	if data.Pressure != nil {
		if metrics.Pressure == nil {
			metrics.Pressure = &model.Pressure{}
		}
		if data.Pressure.CPU != (model.PressureResource{}) {
			metrics.Pressure.CPU = data.Pressure.CPU
		}
		if data.Pressure.Memory != (model.PressureResource{}) {
			metrics.Pressure.Memory = data.Pressure.Memory
		}
		if data.Pressure.IO != (model.PressureResource{}) {
			metrics.Pressure.IO = data.Pressure.IO
		}
	}
	if data.Filesystems != nil {
		metrics.Filesystems = data.Filesystems
	}
	if data.Network != nil {
		metrics.Network = data.Network
	}
	if data.Thermal != nil {
		metrics.Thermal = data.Thermal
	}
	if data.Processes != nil {
		metrics.Processes = data.Processes
	}
	if data.Systemd != nil {
		metrics.Systemd = data.Systemd
	}
	if data.Kernel != nil {
		metrics.Kernel = data.Kernel
	}
	if data.Disks != nil {
		metrics.Disks = data.Disks
	}
	if data.TCP != nil {
		metrics.TCP = data.TCP
	}
	if data.Conntrack != nil {
		metrics.Conntrack = data.Conntrack
	}
	if data.DeviceHealth != nil {
		metrics.DeviceHealth = data.DeviceHealth
	}
	if data.DeviceHealthCoverage != nil {
		metrics.DeviceHealthCoverage = data.DeviceHealthCoverage
	}
	if data.TimeSync != nil {
		metrics.TimeSync = data.TimeSync
	}
	if data.Resources != nil {
		metrics.Resources = data.Resources
	}
	if data.Privileges != nil {
		metrics.Privileges = data.Privileges
	}
	if data.CgroupV2 != nil {
		metrics.CgroupV2 = data.CgroupV2
	}
	if data.Containers != nil {
		metrics.Containers = data.Containers
	}
	if data.ZFSPools != nil {
		metrics.ZFSPools = data.ZFSPools
	}
	if data.Security != nil {
		metrics.Security = data.Security
	}
	if data.SoftwareRAID != nil {
		metrics.SoftwareRAID = data.SoftwareRAID
	}
	if data.LVM != nil {
		metrics.LVM = data.LVM
	}
	if data.MountChecks != nil {
		metrics.MountChecks = data.MountChecks
	}
	if data.NetworkState != nil {
		metrics.NetworkState = data.NetworkState
	}
	if data.DNSResolution != nil {
		metrics.DNSResolution = data.DNSResolution
	}
	if data.GatewayCheck != nil {
		metrics.GatewayCheck = data.GatewayCheck
	}
	if data.PathMTUCheck != nil {
		metrics.PathMTUCheck = data.PathMTUCheck
	}
	if data.HTTPCheck != nil {
		metrics.HTTPCheck = data.HTTPCheck
	}
	if data.ICMPCheck != nil {
		metrics.ICMPCheck = data.ICMPCheck
	}
	if data.IPv6Check != nil {
		metrics.IPv6Check = data.IPv6Check
	}
	if data.DeletedFiles != nil {
		metrics.DeletedFiles = data.DeletedFiles
	}
	if data.Hardware != nil {
		metrics.Hardware = data.Hardware
	}
	if data.Trends != nil {
		metrics.Trends = data.Trends
	}
	if data.PackageActivity != nil {
		metrics.PackageActivity = data.PackageActivity
	}
	if data.PackageUpdates != nil {
		metrics.PackageUpdates = data.PackageUpdates
	}
	if data.Logins != nil {
		metrics.Logins = data.Logins
	}
	if data.SudoCommands != nil {
		metrics.SudoCommands = data.SudoCommands
	}
}

func compactStatuses(statuses []model.CollectionStatus) []model.CollectionStatus {
	byName := make(map[string]model.CollectionStatus, len(statuses))
	for _, status := range statuses {
		previous, exists := byName[status.Collector]
		if !exists {
			byName[status.Collector] = status
			continue
		}
		if status.Status == "error" || previous.Status == "ok" {
			previous.Status = status.Status
		}
		if status.Detail != "" && !strings.Contains(previous.Detail, status.Detail) {
			if previous.Detail != "" {
				previous.Detail += "; "
			}
			previous.Detail += status.Detail
		}
		byName[status.Collector] = previous
	}
	result := make([]model.CollectionStatus, 0, len(byName))
	for _, status := range byName {
		result = append(result, status)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Collector < result[j].Collector })
	return result
}

func collectionStatus(name string, data collect.Data, err error) model.CollectionStatus {
	status := model.CollectionStatus{Collector: name, Status: "ok"}
	for _, diagnostic := range data.Diagnostics {
		if diagnostic.Status == "ok" {
			continue
		}
		if status.Status != "error" {
			status.Status = diagnostic.Status
		}
		if status.Detail != "" {
			status.Detail += "; "
		}
		status.Detail += diagnostic.Detail
	}
	if err != nil {
		status.Status = "error"
		if status.Detail != "" {
			status.Detail += "; "
		}
		status.Detail += err.Error()
	}
	return status
}
