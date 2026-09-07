package app

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

type trendTestCollector struct{ calls atomic.Int32 }

func (c *trendTestCollector) Name() string { return "trend-test" }

func (c *trendTestCollector) Collect(context.Context) (collect.Data, error) {
	c.calls.Add(1)
	return collect.Data{CPU: &model.CPU{}}, nil
}

func (c *trendTestCollector) Trends(samples []collect.Data) []model.Trend {
	return []model.Trend{{Name: "test.calls", Unit: "count", Values: []float64{float64(len(samples))}}}
}

func TestRunSamplesTrendsWithinSingleWindow(t *testing.T) {
	collector := &trendTestCollector{}
	started := time.Now()
	report := Run(context.Background(), Config{Duration: 35 * time.Millisecond, SampleInterval: 10 * time.Millisecond}, []collect.Collector{collector})
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("sampling window was unexpectedly extended: %s", elapsed)
	}
	if collector.calls.Load() < 3 { // baseline, at least one interval, final
		t.Fatalf("expected boundary and intermediate samples, got %d", collector.calls.Load())
	}
	if len(report.Metrics.Trends) != 1 || report.Metrics.Trends[0].Name != "test.calls" {
		t.Fatalf("unexpected trends: %#v", report.Metrics.Trends)
	}
	for _, status := range report.Collection {
		if status.Collector == "" {
			t.Fatalf("trend collection added an unnamed status: %+v", report.Collection)
		}
	}
}

type failedDeltaCollector struct{}

func (failedDeltaCollector) Name() string { return "failed-delta" }
func (failedDeltaCollector) Collect(context.Context) (collect.Data, error) {
	return collect.Data{CPU: &model.CPU{Load1: 10}}, nil
}
func (failedDeltaCollector) Delta(collect.Data, collect.Data) (collect.Data, error) {
	return collect.Data{}, fmt.Errorf("counter interval invalid")
}
func TestDeltaFailureDoesNotInventIdleCPU(t *testing.T) {
	r := Run(context.Background(), Config{}, []collect.Collector{failedDeltaCollector{}})
	if r.Metrics.CPU != nil || len(r.Collection) != 1 || r.Collection[0].Status != "error" {
		t.Fatalf("lost delta failure: %+v", r)
	}
}
func TestOptionalDiagnosticsPreserveGauges(t *testing.T) {
	data := collect.Data{Memory: &model.Memory{TotalBytes: 1024}, Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "optional pressure file missing"}}}
	status := collectionStatus("memory", data, nil)
	if status.Status != "unavailable" || status.Detail == "" {
		t.Fatalf("missing diagnostic: %+v", status)
	}
}

func TestCompactionRetainsBoundaryAndDeltaErrors(t *testing.T) {
	statuses := compactStatuses([]model.CollectionStatus{{Collector: "cpu", Status: "error", Detail: "read failed"}, {Collector: "cpu", Status: "ok"}, {Collector: "cpu", Status: "error", Detail: "delta failed"}, {Collector: "cpu", Status: "error", Detail: "read failed"}})
	if len(statuses) != 1 || statuses[0].Status != "error" || statuses[0].Detail != "read failed; delta failed" {
		t.Fatalf("lost diagnostic: %+v", statuses)
	}
}
