package cpu

import (
	"context"
	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseStat(t *testing.T) {
	fixture, err := os.Open("testdata/stat.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	got, err := ParseStat(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total.Total() != 969 || got.Total.IOWait != 10 || len(got.PerCPU) != 2 {
		t.Fatalf("unexpected stat: %#v", got)
	}
	if got.ContextSwitches != 456 || got.Runnable != 2 || got.Blocked != 1 {
		t.Fatalf("unexpected counters: %#v", got)
	}
}

func TestParseLoad(t *testing.T) {
	got, err := ParseLoad(strings.NewReader("1.25 0.75 0.50 3/123 999\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got.One != 1.25 || got.Running != 3 || got.Total != 123 {
		t.Fatalf("unexpected load: %#v", got)
	}
}

func TestParsePressure(t *testing.T) {
	fixture, err := os.Open("testdata/pressure.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	got, err := ParsePressure(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if got.Some.Avg10 != 1.25 || got.Some.Total != 123 || got.Full != nil {
		t.Fatalf("unexpected PSI: %#v", got)
	}
}

func TestParsePressureAcceptsZeroRecord(t *testing.T) {
	got, err := ParsePressure(strings.NewReader("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"))
	if err != nil || got.Some.Total != 0 {
		t.Fatalf("zero pressure record rejected: %#v, %v", got, err)
	}
}

func TestBetween(t *testing.T) {
	start := Snapshot{At: time.Unix(100, 0), Stat: Stat{Total: Times{User: 100, System: 50, Idle: 850, IOWait: 10}}}
	end := Snapshot{At: time.Unix(110, 0), Stat: Stat{Total: Times{User: 130, System: 70, Idle: 890, IOWait: 20}, ContextSwitches: 5, Runnable: 2}}
	got, err := Between(start, end)
	if err != nil {
		t.Fatal(err)
	}
	if got.Utilization != 0.6 || got.User != 0.3 || got.System != 0.2 || got.IOWait != 0.1 {
		t.Fatalf("unexpected delta: %#v", got)
	}
}

func TestParseStatRejectsMalformedCPU(t *testing.T) {
	if _, err := ParseStat(strings.NewReader("cpu 1 nope 3 4\n")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestMissingProcFilesDoNotCreateSnapshot(t *testing.T) {
	data, err := (Collector{ProcRoot: t.TempDir()}).Collect(context.Background())
	if err == nil || data.Snapshot != nil {
		t.Fatalf("fatal error created snapshot: %+v, %v", data, err)
	}
}

func TestMissingBaselinePreservesGauges(t *testing.T) {
	last := collect.Data{CPU: &model.CPU{Load1: 2}}
	got, err := (Collector{}).Delta(collect.Data{}, last)
	if err == nil || got.CPU == nil || got.CPU.Load1 != 2 || got.CPU.Sampled == nil || *got.CPU.Sampled {
		t.Fatalf("invalid fallback: %+v %v", got, err)
	}
}

func TestMalformedOptionalPSIPreservesCore(t *testing.T) {
	root := t.TempDir()
	for name, contents := range map[string]string{"stat": "cpu 100 0 0 900 0 0 0 0\n", "loadavg": "0.01 0.02 0.03 1/20 3\n", "pressure/cpu": "broken\n"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := (Collector{ProcRoot: root}).Collect(context.Background())
	if err == nil || got.CPU == nil || got.Snapshot == nil {
		t.Fatalf("lost core facts: %+v %v", got, err)
	}
}
