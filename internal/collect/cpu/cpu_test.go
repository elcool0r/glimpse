package cpu

import (
	"context"
	"encoding/json"
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

func TestParseStatCountsOnlyNumberedCPUEntries(t *testing.T) {
	stat, err := ParseStat(strings.NewReader("cpu 1 0 0 9\ncpu0 1 0 0 9\ncpu1 1 0 0 9\ncpu_frequency 1000\n"))
	if err != nil || len(stat.PerCPU) != 2 {
		t.Fatalf("per CPU population = %#v, %v", stat.PerCPU, err)
	}
}

func TestCollectorCarriesHostCPUCountFromProcStatPopulation(t *testing.T) {
	start := Snapshot{At: time.Unix(1, 0), Stat: Stat{PerCPU: map[string]Times{"cpu0": {}, "cpu1": {}, "cpu2": {}, "cpu3": {}, "cpu4": {}, "cpu5": {}, "cpu6": {}, "cpu7": {}}, Total: Times{Idle: 100}}}
	end := Snapshot{At: time.Unix(2, 0), Stat: Stat{PerCPU: start.Stat.PerCPU, Total: Times{User: 20, Idle: 180}}, Load: Load{One: 2}}
	got, err := (Collector{}).Delta(collect.Data{Snapshot: start}, collect.Data{Snapshot: end, CPU: &model.CPU{HostCPUCount: 8}})
	if err != nil || got.CPU == nil || got.CPU.HostCPUCount != 8 {
		t.Fatalf("host CPU population = %#v, %v", got.CPU, err)
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

func TestBetweenRejectsDecreasingIowaitInsteadOfNegativeUtilization(t *testing.T) {
	start := Snapshot{At: time.Unix(100, 0), Stat: Stat{Total: Times{User: 100, Idle: 100, IOWait: 100}}}
	end := Snapshot{At: time.Unix(110, 0), Stat: Stat{Total: Times{User: 110, Idle: 130, IOWait: 80}}}
	if _, err := Between(start, end); err == nil {
		t.Fatal("expected incoherent interval error")
	}
	data, err := (Collector{}).Delta(collect.Data{Snapshot: start}, collect.Data{Snapshot: end, CPU: &model.CPU{Load1: 3, Runnable: 2}})
	if err == nil || data.CPU == nil || data.CPU.Sampled == nil || *data.CPU.Sampled || data.CPU.Load1 != 3 || data.CPU.Utilization != 0 || data.CPU.IOWait != 0 {
		t.Fatalf("invalid fallback: %#v, %v", data, err)
	}
	encoded, marshalErr := json.Marshal(data.CPU)
	if marshalErr != nil || !strings.Contains(string(encoded), `"sampled":false`) || strings.Contains(string(encoded), "-") {
		t.Fatalf("fallback JSON=%s err=%v", encoded, marshalErr)
	}
}

func TestTrendsOmitsIncoherentCPUInterval(t *testing.T) {
	start := Snapshot{At: time.Unix(1, 0), Stat: Stat{Total: Times{User: 100, Idle: 100, IOWait: 100}}}
	bad := Snapshot{At: time.Unix(2, 0), Stat: Stat{Total: Times{User: 110, Idle: 130, IOWait: 80}}}
	good := Snapshot{At: time.Unix(3, 0), Stat: Stat{Total: Times{User: 120, Idle: 140, IOWait: 80}}}
	found := false
	for _, trend := range (Collector{}).Trends([]collect.Data{{Snapshot: start}, {Snapshot: bad}, {Snapshot: good}}) {
		if trend.Name == "cpu.utilization" && len(trend.Values) != 1 {
			t.Fatalf("utilization trends=%#v", trend)
		}
		if trend.Name == "cpu.utilization" {
			found = true
		}
	}
	if !found {
		t.Fatal("valid CPU utilization trend was lost")
	}
}

func TestBetweenRejectsEveryCPUTimeComponentRegression(t *testing.T) {
	for _, field := range []func(*Times){func(t *Times) { t.User-- }, func(t *Times) { t.Nice-- }, func(t *Times) { t.System-- }, func(t *Times) { t.Idle-- }, func(t *Times) { t.IOWait-- }, func(t *Times) { t.IRQ-- }, func(t *Times) { t.SoftIRQ-- }, func(t *Times) { t.Steal-- }} {
		start := Snapshot{At: time.Unix(1, 0), Stat: Stat{Total: Times{User: 10, Nice: 10, System: 10, Idle: 10, IOWait: 10, IRQ: 10, SoftIRQ: 10, Steal: 10}}}
		end := start
		end.At = end.At.Add(time.Second)
		field(&end.Stat.Total)
		if _, err := Between(start, end); err == nil {
			t.Fatal("expected component regression error")
		}
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
