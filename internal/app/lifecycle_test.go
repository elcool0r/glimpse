package app

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

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
