package app

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

type stagedTrendCollector struct {
	cooperative bool
	release     chan struct{}
	entered     chan struct{}
	enterOnce   sync.Once
	calls       atomic.Int32
	active      atomic.Int32
	maxActive   atomic.Int32
	deltaCalls  atomic.Int32
	deadlineNS  atomic.Int64
}

func (c *stagedTrendCollector) Name() string { return "staged-trend" }
func (c *stagedTrendCollector) Collect(ctx context.Context) (collect.Data, error) {
	call := c.calls.Add(1)
	active := c.active.Add(1)
	defer c.active.Add(-1)
	for {
		maximum := c.maxActive.Load()
		if active <= maximum || c.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	if call == 1 {
		return collect.Data{Snapshot: call}, nil
	}
	if deadline, ok := ctx.Deadline(); ok {
		c.deadlineNS.Store(int64(time.Until(deadline)))
	}
	c.enterOnce.Do(func() { close(c.entered) })
	if c.cooperative {
		<-ctx.Done()
		return collect.Data{}, ctx.Err()
	}
	<-c.release
	return collect.Data{Memory: &model.Memory{TotalBytes: 99}}, nil
}
func (c *stagedTrendCollector) Trends([]collect.Data) []model.Trend {
	return []model.Trend{{Name: "stalled.false", Unit: "count", Values: []float64{1}}}
}
func (c *stagedTrendCollector) Delta(collect.Data, collect.Data) (collect.Data, error) {
	c.deltaCalls.Add(1)
	return collect.Data{Memory: &model.Memory{TotalBytes: 99}}, nil
}

type fastTrendCollector struct{ calls atomic.Int32 }

func (c *fastTrendCollector) Name() string { return "fast-trend" }
func (c *fastTrendCollector) Collect(context.Context) (collect.Data, error) {
	call := c.calls.Add(1)
	return collect.Data{
		Snapshot: call,
		Thermal:  []model.Thermal{{Name: "fast", TemperatureC: float64(call)}},
	}, nil
}
func (c *fastTrendCollector) Trends(samples []collect.Data) []model.Trend {
	values := make([]float64, 0, len(samples))
	for _, sample := range samples {
		if call, ok := sample.Snapshot.(int32); ok {
			values = append(values, float64(call))
		}
	}
	return []model.Trend{{Name: "fast.calls", Unit: "count", Values: values}}
}

type boundaryStallDelta struct {
	release    chan struct{}
	calls      atomic.Int32
	deltaCalls atomic.Int32
}

func (c *boundaryStallDelta) Name() string { return "boundary-stall" }
func (c *boundaryStallDelta) Collect(context.Context) (collect.Data, error) {
	c.calls.Add(1)
	<-c.release
	return collect.Data{Memory: &model.Memory{TotalBytes: 55}}, nil
}
func (c *boundaryStallDelta) Delta(collect.Data, collect.Data) (collect.Data, error) {
	c.deltaCalls.Add(1)
	return collect.Data{Memory: &model.Memory{TotalBytes: 55}}, nil
}

// slowCollector takes longer than a boundary budget allows.
type slowCollector struct{ delay time.Duration }

func (slowCollector) Name() string { return "slow" }
func (c slowCollector) Collect(ctx context.Context) (collect.Data, error) {
	select {
	case <-time.After(c.delay):
	case <-ctx.Done():
		return collect.Data{}, ctx.Err()
	}
	return collect.Data{Thermal: []model.Thermal{{Name: "sensor", TemperatureC: 40}}}, nil
}

type steadyCollector struct{}

func (steadyCollector) Name() string { return "memory" }
func (steadyCollector) Collect(context.Context) (collect.Data, error) {
	return collect.Data{Memory: &model.Memory{TotalBytes: 1 << 30, AvailableBytes: 1 << 29, AvailableFraction: .5}}, nil
}

type hostCPUCountCollector struct{}

func (hostCPUCountCollector) Name() string { return "cpu" }
func (hostCPUCountCollector) Collect(context.Context) (collect.Data, error) {
	return collect.Data{Snapshot: struct{}{}, CPU: &model.CPU{HostCPUCount: 8}}, nil
}
func (hostCPUCountCollector) Delta(collect.Data, collect.Data) (collect.Data, error) {
	return collect.Data{CPU: &model.CPU{HostCPUCount: 8, Load1: 2}}, nil
}

func TestRunPrefersProcStatHostCPUCountOverRuntimeAffinity(t *testing.T) {
	report := Run(context.Background(), Config{}, []collect.Collector{hostCPUCountCollector{}})
	if report.Host.CPUCount != 8 {
		t.Fatalf("host cpu count = %d, want proc-stat population 8", report.Host.CPUCount)
	}
}

type blockingCollector struct{ release <-chan struct{} }

func (blockingCollector) Name() string { return "blocking" }
func (c blockingCollector) Collect(context.Context) (collect.Data, error) {
	<-c.release
	return collect.Data{}, nil
}

type slowDeltaCollector struct{ delay time.Duration }

func (slowDeltaCollector) Name() string { return "slow-delta" }
func (c slowDeltaCollector) Collect(context.Context) (collect.Data, error) {
	time.Sleep(c.delay)
	return collect.Data{Snapshot: time.Now()}, nil
}
func (slowDeltaCollector) Delta(collect.Data, collect.Data) (collect.Data, error) {
	return collect.Data{}, nil
}

// A boundary that runs out of its own budget is missing coverage, not a failed
// report. Previously baseline and final collection shared one deadline with the
// sampling window, so exceeding it marked sampling as errored and collapsed
// every collected metric into INSUFFICIENT DATA.
func TestBoundaryOverrunKeepsTheCollectedReport(t *testing.T) {
	report := Run(context.Background(), Config{BoundaryTimeout: 30 * time.Millisecond},
		[]collect.Collector{slowCollector{delay: time.Second}, steadyCollector{}})
	analyze.Report(&report)

	if report.Metrics.Memory == nil {
		t.Fatal("a slow collector erased the metrics that were collected successfully")
	}
	for _, status := range report.Collection {
		if status.Collector == "sampling" {
			t.Fatalf("a boundary timeout was reported as an interrupted run: %+v", status)
		}
	}
	if report.Score.Status == model.SeverityUnknown {
		t.Fatalf("partial coverage reported as insufficient data: %+v", report.Score)
	}
	var noted bool
	for _, status := range report.Collection {
		noted = noted || (status.Collector == "slow" && status.Status != "ok")
	}
	if !noted {
		t.Fatalf("the collector that could not finish left no diagnostic: %+v", report.Collection)
	}
}

func TestNonCooperativeCollectorDoesNotOutliveBoundary(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	started := time.Now()
	report := Run(context.Background(), Config{BoundaryTimeout: 20 * time.Millisecond}, []collect.Collector{blockingCollector{release: release}, steadyCollector{}})
	if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
		t.Fatalf("Run waited for a collector that ignored cancellation: %s", elapsed)
	}
	var noted bool
	for _, status := range report.Collection {
		noted = noted || (status.Collector == "blocking" && status.Status == "error" && strings.Contains(status.Detail, "deadline exceeded"))
	}
	if !noted {
		t.Fatalf("missing deadline diagnostic for non-cooperative collector: %+v", report.Collection)
	}
}

func TestBoundaryExpiryExcludesCollectorFromFinalAndDelta(t *testing.T) {
	collector := &boundaryStallDelta{release: make(chan struct{})}
	report := Run(context.Background(), Config{BoundaryTimeout: 10 * time.Millisecond}, []collect.Collector{collector})

	if got := collector.calls.Load(); got != 1 {
		t.Fatalf("expired baseline collector ran %d times, want once", got)
	}
	if got := collector.deltaCalls.Load(); got != 0 {
		t.Fatalf("excluded collector derived %d deltas, want none", got)
	}
	if report.Metrics.Memory != nil {
		t.Fatalf("excluded collector produced metrics: %+v", report.Metrics.Memory)
	}
	close(collector.release)
}

func TestAwaitCollectionRejectsResultFinishedAfterDeadline(t *testing.T) {
	deadline := time.Now().Add(10 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	results := make(chan collectionResult, 1)
	results <- collectionResult{
		index:    0,
		data:     collect.Data{Memory: &model.Memory{TotalBytes: 99}},
		finished: deadline.Add(time.Millisecond),
	}

	data, status, unfinished := awaitCollection(
		ctx,
		[]collect.Collector{slowCollector{}},
		make([]collect.Data, 1),
		make([]model.CollectionStatus, 1),
		[]bool{true},
		1,
		results,
	)

	if data[0].Memory != nil {
		t.Fatalf("late result was applied: %+v", data[0].Memory)
	}
	if !unfinished[0] {
		t.Fatal("late collector was not left unfinished for exclusion")
	}
	if status[0].Status != "error" || !strings.Contains(status[0].Detail, context.DeadlineExceeded.Error()) {
		t.Fatalf("late collector status = %+v, want deadline error", status[0])
	}
}

func TestCooperativeTrendExpiryIsBoundedAndExcluded(t *testing.T) {
	collector := &stagedTrendCollector{
		cooperative: true,
		release:     make(chan struct{}),
		entered:     make(chan struct{}),
	}
	started := time.Now()
	report := Run(context.Background(), Config{
		Duration:           45 * time.Millisecond,
		SampleInterval:     5 * time.Millisecond,
		ObservationTimeout: 10 * time.Millisecond,
	}, []collect.Collector{collector})

	if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
		t.Fatalf("cooperative trend expiry extended the run: %s", elapsed)
	}
	if got := collector.calls.Load(); got != 2 {
		t.Fatalf("expired trend collector ran %d times, want baseline and one observation", got)
	}
	if got := collector.maxActive.Load(); got != 1 {
		t.Fatalf("collector had %d concurrent calls, want at most one", got)
	}
	if got := collector.deltaCalls.Load(); got != 0 {
		t.Fatalf("excluded collector derived %d deltas, want none", got)
	}
	if hasTrend(report.Metrics.Trends, "stalled.false") {
		t.Fatalf("excluded collector built a trend: %+v", report.Metrics.Trends)
	}
	assertCollectorDeadline(t, report, collector.Name(), context.DeadlineExceeded.Error())
}

func TestNonCooperativeTrendExpiryPreservesFastPeerAndLateResultCannotMutateReport(t *testing.T) {
	stalled := &stagedTrendCollector{
		release: make(chan struct{}),
		entered: make(chan struct{}),
	}
	fast := &fastTrendCollector{}
	started := time.Now()
	report := Run(context.Background(), Config{
		Duration:           45 * time.Millisecond,
		SampleInterval:     5 * time.Millisecond,
		ObservationTimeout: 10 * time.Millisecond,
	}, []collect.Collector{stalled, fast})

	if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
		t.Fatalf("non-cooperative trend collector extended the run: %s", elapsed)
	}
	if got := stalled.calls.Load(); got != 2 {
		t.Fatalf("stalled collector ran %d times, want baseline and one observation", got)
	}
	if got := stalled.maxActive.Load(); got != 1 {
		t.Fatalf("stalled collector had %d concurrent calls, want at most one", got)
	}
	if got := stalled.deltaCalls.Load(); got != 0 {
		t.Fatalf("excluded collector derived %d deltas, want none", got)
	}
	if report.Metrics.Memory != nil || hasTrend(report.Metrics.Trends, "stalled.false") {
		t.Fatalf("stalled collector affected report: %+v", report.Metrics)
	}
	fastCalls := fast.calls.Load()
	if fastCalls < 4 {
		t.Fatalf("fast peer stopped with stalled collector: %d calls", fastCalls)
	}
	if len(report.Metrics.Thermal) != 1 || report.Metrics.Thermal[0].TemperatureC != float64(fastCalls) {
		t.Fatalf("fast peer final observation was not preserved: calls=%d thermal=%+v", fastCalls, report.Metrics.Thermal)
	}
	if !hasTrend(report.Metrics.Trends, "fast.calls") {
		t.Fatalf("fast peer trend was not preserved: %+v", report.Metrics.Trends)
	}
	assertCollectorDeadline(t, report, stalled.Name(), context.DeadlineExceeded.Error())

	close(stalled.release)
	deadline := time.Now().Add(100 * time.Millisecond)
	for stalled.active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stalled.active.Load() != 0 {
		t.Fatal("late collector did not exit after release")
	}
	if report.Metrics.Memory != nil || hasTrend(report.Metrics.Trends, "stalled.false") {
		t.Fatalf("late result mutated returned report: %+v", report.Metrics)
	}
}

func TestObservationDeadlineUsesRemainingSampleWindow(t *testing.T) {
	collector := &stagedTrendCollector{
		cooperative: true,
		release:     make(chan struct{}),
		entered:     make(chan struct{}),
	}
	Run(context.Background(), Config{
		Duration:           70 * time.Millisecond,
		SampleInterval:     50 * time.Millisecond,
		ObservationTimeout: time.Second,
	}, []collect.Collector{collector})

	remaining := time.Duration(collector.deadlineNS.Load())
	if remaining <= 0 || remaining >= 40*time.Millisecond {
		t.Fatalf("observation deadline was not capped by the remaining sample window: %s", remaining)
	}
}

func TestParentCancellationDuringTrendObservationRemainsGlobal(t *testing.T) {
	collector := &stagedTrendCollector{
		cooperative: true,
		release:     make(chan struct{}),
		entered:     make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	reports := make(chan model.Report, 1)
	go func() {
		reports <- Run(ctx, Config{
			Duration:           time.Second,
			SampleInterval:     5 * time.Millisecond,
			ObservationTimeout: 500 * time.Millisecond,
		}, []collect.Collector{collector})
	}()
	select {
	case <-collector.entered:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("trend observation did not start")
	}
	cancel()
	var report model.Report
	select {
	case report = <-reports:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("parent cancellation did not stop the run")
	}
	var interrupted bool
	for _, status := range report.Collection {
		interrupted = interrupted || (status.Collector == "sampling" && status.Status == "error" && strings.Contains(status.Detail, context.Canceled.Error()))
	}
	if !interrupted {
		t.Fatalf("parent cancellation was not reported globally: %+v", report.Collection)
	}
}

func hasTrend(trends []model.Trend, name string) bool {
	for _, trend := range trends {
		if trend.Name == name {
			return true
		}
	}
	return false
}

func assertCollectorDeadline(t *testing.T, report model.Report, collector, detail string) {
	t.Helper()
	for _, status := range report.Collection {
		if status.Collector == collector && status.Status == "error" && strings.Contains(status.Detail, detail) {
			return
		}
	}
	t.Fatalf("missing %s deadline diagnostic: %+v", collector, report.Collection)
}

func TestSampleDurationExcludesBaselineCollection(t *testing.T) {
	const delay = 25 * time.Millisecond
	started := time.Now()
	report := Run(context.Background(), Config{Duration: 10 * time.Millisecond}, []collect.Collector{slowDeltaCollector{delay: delay}})
	total := time.Since(started)
	sampled := time.Duration(report.SampleDurationSeconds * float64(time.Second))
	if total-sampled < delay/2 {
		t.Fatalf("sample duration included baseline setup: total=%s sampled=%s", total, sampled)
	}
	if sampled < 10*time.Millisecond {
		t.Fatalf("sample duration excluded the requested sampling window: %s", sampled)
	}
}

// An interrupted run is a different thing from a slow one, and must still
// invalidate the verdict.
func TestCancelledRunIsReportedAsInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report := Run(ctx, Config{}, []collect.Collector{steadyCollector{}})
	analyze.Report(&report)
	var interrupted bool
	for _, status := range report.Collection {
		interrupted = interrupted || (status.Collector == "sampling" && status.Status == "error")
	}
	if !interrupted {
		t.Fatalf("cancellation not recorded: %+v", report.Collection)
	}
	if report.Score.Status != model.SeverityUnknown {
		t.Fatalf("interrupted run kept a verdict: %+v", report.Score)
	}
}

type countingStatic struct{ calls atomic.Int32 }

func (c *countingStatic) Name() string { return "static" }
func (c *countingStatic) Static()      {}
func (c *countingStatic) Collect(context.Context) (collect.Data, error) {
	c.calls.Add(1)
	return collect.Data{Systemd: &model.Systemd{Available: true}}, nil
}

type countingDelta struct{ calls atomic.Int32 }

func (c *countingDelta) Name() string { return "counter" }
func (c *countingDelta) Static()      {} // must be ignored: merge needs both boundaries
func (c *countingDelta) Collect(context.Context) (collect.Data, error) {
	c.calls.Add(1)
	return collect.Data{Snapshot: c.calls.Load()}, nil
}
func (c *countingDelta) Delta(collect.Data, collect.Data) (collect.Data, error) {
	return collect.Data{CPU: &model.CPU{}}, nil
}

// Every non-delta collector previously ran at both boundaries with the first
// result discarded, doubling smartctl, journalctl, LVM and ss cost against a
// fixed overhead budget.
func TestStaticCollectorsRunOnlyOnce(t *testing.T) {
	static := &countingStatic{}
	counter := &countingDelta{}
	report := Run(context.Background(), Config{}, []collect.Collector{static, counter})
	if got := static.calls.Load(); got != 1 {
		t.Fatalf("static collector ran %d times, want 1", got)
	}
	if got := counter.calls.Load(); got != 2 {
		t.Fatalf("delta collector ran %d times, want both boundaries", got)
	}
	if report.Metrics.Systemd == nil {
		t.Fatal("the single static observation was not applied")
	}
	for _, status := range report.Collection {
		if status.Collector == "static" && strings.Contains(status.Detail, "deadline") {
			t.Fatalf("unexpected diagnostic: %+v", status)
		}
	}
}
