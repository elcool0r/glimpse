package main

import (
	"context"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/app"
	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

// The TCP collector was written, unit-tested and documented, but never added to
// the profile, so its model field, its three findings and its report row were
// unreachable in the shipped binary and nothing failed. This pins the registry
// against the names the rest of the program reasons about.
func TestDefaultProfileRegistersEveryAnalyzedCollector(t *testing.T) {
	required := []string{
		"cpu", "memory", "filesystems", "disk", "network", "tcp", "network-state",
		"thermal", "processes", "systemd", "kernel", "time-sync", "resources",
		"security", "cgroup-v2", "zfs", "storage", "hardware-errors", "device-health",
		"deleted-files", "package-activity",
	}
	registered := map[string]bool{}
	for _, collector := range defaultCollectors(false, false) {
		if registered[collector.Name()] {
			t.Fatalf("duplicate collector name %q: statuses would be merged", collector.Name())
		}
		registered[collector.Name()] = true
	}
	for _, name := range required {
		if !registered[name] {
			t.Errorf("collector %q is analyzed or rendered but never registered", name)
		}
	}
	if !contains(defaultCollectors(true, false), "containers") {
		t.Error("container inspection not registered when a runtime is available")
	}
	if contains(defaultCollectors(false, false), "containers") {
		t.Error("container inspection registered while disabled")
	}
	activeCheckCollectors := []string{"dns-resolution", "gateway-ping", "path-mtu", "http-check", "icmp-check", "ipv6-check"}
	for _, name := range activeCheckCollectors {
		if contains(defaultCollectors(false, false), name) {
			t.Errorf("%s registered with external checks disabled", name)
		}
		if !contains(defaultCollectors(false, true), name) {
			t.Errorf("%s not registered with external checks enabled (the default)", name)
		}
	}
}

// Collectors that shell out must be marked static, or every optional command
// runs twice per report with the first result discarded by merge.
func TestOptionalCommandCollectorsAreStatic(t *testing.T) {
	for _, name := range []string{"kernel", "time-sync", "zfs", "storage", "network-state", "device-health", "security", "filesystems", "thermal", "resources", "hardware-errors", "dns-resolution", "gateway-ping", "path-mtu", "http-check", "icmp-check", "ipv6-check", "deleted-files", "package-activity"} {
		collector := find(defaultCollectors(false, true), name)
		if collector == nil {
			t.Fatalf("%s missing from the profile", name)
		}
		if _, ok := collector.(collect.StaticCollector); !ok {
			t.Errorf("%s runs at both boundaries but only its final result is used", name)
		}
	}
	// Counter-based collectors must not be static: merge needs both boundaries.
	// systemd joined this group once it started tracking per-unit restart
	// counts across the sample, alongside the gauge-only failed-unit list.
	for _, name := range []string{"cpu", "memory", "disk", "network", "tcp", "processes", "systemd"} {
		collector := find(defaultCollectors(false, false), name)
		if _, ok := collector.(collect.DeltaCollector); !ok {
			t.Errorf("%s should derive sampled values from two observations", name)
		}
	}
}

// A full run must complete inside its own budget and produce a verdict.
func TestDefaultProfileCompletesAndScores(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the real collectors")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	report := app.Run(ctx, app.Config{Duration: 0, SampleInterval: time.Second, BoundaryTimeout: 20 * time.Second}, defaultCollectors(false, false))
	analyze.Report(&report)
	if report.SchemaVersion != model.SchemaVersion {
		t.Fatalf("schema=%d", report.SchemaVersion)
	}
	if len(report.Collection) == 0 {
		t.Fatal("no collection statuses recorded")
	}
	for _, status := range report.Collection {
		if status.Collector == "sampling" {
			t.Fatalf("uninterrupted run reported as interrupted: %+v", status)
		}
	}
}

func contains(collectors []collect.Collector, name string) bool {
	return find(collectors, name) != nil
}

func find(collectors []collect.Collector, name string) collect.Collector {
	for _, collector := range collectors {
		if collector.Name() == name {
			return collector
		}
	}
	return nil
}
