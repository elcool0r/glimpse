package cgroupv2

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

func TestCollectorRespectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Collect(ctx); err == nil {
		t.Fatal("expected cancelled context error")
	}
}

func TestParsePath(t *testing.T) {
	p, ok := ParsePath("0::/user.slice/user-1000.slice\n")
	if !ok || p != "/user.slice/user-1000.slice" {
		t.Fatalf("%q %v", p, ok)
	}
}
func TestParseKeyValues(t *testing.T) {
	got := ParseKeyValues("oom 2\nbad x\noom_kill 1\n")
	if got["oom"] != 2 || got["oom_kill"] != 1 {
		t.Fatal(got)
	}
}
func TestCounterDelta(t *testing.T) {
	if counterDelta(5, 3) != 0 || counterDelta(3, 5) != 2 {
		t.Fatal("bad delta")
	}
}

func TestIsContainerizedRecognizesLXCAndSystemdNspawn(t *testing.T) {
	for _, path := range []string{
		"/lxc.payload.web",
		"/lxc/web",
		"/machine.slice/machine-build.scope",
	} {
		if !isContainerized(path) {
			t.Fatalf("%q was not recognized as containerized", path)
		}
	}
	if isContainerized("/user.slice/user-1000.slice/session-2.scope") {
		t.Fatal("ordinary user scope must not be classified as containerized")
	}
}

func TestCollectSetsPerFileValidityAndReportsFailures(t *testing.T) {
	files := map[string]string{
		"/proc/self/cgroup":                          "0::/slice/a\n",
		"/sys/fs/cgroup/cgroup.controllers":          "memory pids cpu\n",
		"/sys/fs/cgroup/slice/a/memory.current":      "0\n",
		"/sys/fs/cgroup/slice/a/memory.max":          "max\n",
		"/sys/fs/cgroup/slice/a/memory.swap.current": "7\n",
		"/sys/fs/cgroup/slice/a/memory.swap.max":     "bad\n",
		"/sys/fs/cgroup/slice/a/pids.current":        "0\n",
		"/sys/fs/cgroup/slice/a/pids.max":            "12\n",
		"/sys/fs/cgroup/slice/a/memory.pressure":     "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
		"/sys/fs/cgroup/slice/a/memory.events":       "oom 0\noom_kill 0\n",
		"/sys/fs/cgroup/slice/a/cpu.stat":            "usage_usec 0\nthrottled_usec 0\n",
	}
	read := func(name string) ([]byte, error) {
		if value, ok := files[name]; ok {
			return []byte(value), nil
		}
		return nil, os.ErrNotExist
	}
	c := &Collector{ProcRoot: "/proc", CgroupRoot: "/sys/fs/cgroup", readFile: read, stat: func(string) (os.FileInfo, error) { return fakeInfo{}, nil }}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := data.CgroupV2
	if got == nil || got.MemoryCurrentValid == nil || !*got.MemoryCurrentValid || got.MemoryCurrentBytes != 0 {
		t.Fatalf("zero current must be valid: %+v", got)
	}
	if got.MemoryMaxValid == nil || !*got.MemoryMaxValid || got.MemoryMaxBytes != nil {
		t.Fatalf("max must be valid unlimited: %+v", got)
	}
	if got.MemorySwapMaxValid == nil || *got.MemorySwapMaxValid {
		t.Fatalf("malformed max must be invalid: %+v", got)
	}
	if got.MemoryEventsSampled == nil || !*got.MemoryEventsSampled || got.CPUStatSampled == nil || !*got.CPUStatSampled {
		t.Fatalf("required event groups should be sampled: %+v", got)
	}
	if got.MemoryPressureValid == nil || !*got.MemoryPressureValid || got.MemoryPressure == nil || got.MemoryPressure.SomeAvg10 != 0 {
		t.Fatalf("zero local pressure must be valid: %+v", got)
	}
	if len(data.Diagnostics) != 1 || !strings.Contains(data.Diagnostics[0].Detail, "memory.swap.max") || !strings.Contains(data.Diagnostics[0].Detail, "malformed") {
		t.Fatalf("diagnostics = %+v", data.Diagnostics)
	}
}

func TestCollectRequiredGroupsNeedBothCounters(t *testing.T) {
	files := map[string]string{
		"/proc/self/cgroup":                     "/proc/self/cgroup", // replaced below
		"/sys/fs/cgroup/cgroup.controllers":     "memory pids cpu",
		"/sys/fs/cgroup/slice/a/memory.current": "1", "/sys/fs/cgroup/slice/a/memory.max": "max",
		"/sys/fs/cgroup/slice/a/memory.swap.current": "1", "/sys/fs/cgroup/slice/a/memory.swap.max": "max",
		"/sys/fs/cgroup/slice/a/pids.current": "1", "/sys/fs/cgroup/slice/a/pids.max": "max",
		"/sys/fs/cgroup/slice/a/memory.pressure": "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
		"/sys/fs/cgroup/slice/a/memory.events":   "oom 1", "/sys/fs/cgroup/slice/a/cpu.stat": "usage_usec 1",
	}
	files["/proc/self/cgroup"] = "0::/slice/a\n"
	read := func(name string) ([]byte, error) {
		if value, ok := files[name]; ok {
			return []byte(value), nil
		}
		return nil, errors.New("denied")
	}
	c := &Collector{ProcRoot: "/proc", CgroupRoot: "/sys/fs/cgroup", readFile: read, stat: func(string) (os.FileInfo, error) { return fakeInfo{}, nil }}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if *data.CgroupV2.MemoryEventsSampled || *data.CgroupV2.CPUStatSampled {
		t.Fatalf("incomplete groups sampled: %+v", data.CgroupV2)
	}
	if len(data.Diagnostics) != 2 {
		t.Fatalf("expected one diagnostic per failed group, got %+v", data.Diagnostics)
	}
}

func TestReadMemoryPressureRejectsMalformedAndPreservesLocalScope(t *testing.T) {
	read := func(string) ([]byte, error) {
		return []byte("some avg10=1.25 avg60=0.50 avg300=0.25 total=4\nfull avg10=0.75 avg60=0.20 avg300=0.10 total=2\n"), nil
	}
	got, ok, err := readMemoryPressure(read, "memory.pressure")
	if err != nil || !ok || got.SomeAvg10 != 1.25 || got.FullAvg10 != .75 {
		t.Fatalf("local pressure = %#v, %v, %v", got, ok, err)
	}
	bad := func(string) ([]byte, error) { return []byte("some avg10=nope avg60=0 avg300=0 total=0\n"), nil }
	if _, ok, err := readMemoryPressure(bad, "memory.pressure"); err == nil || ok {
		t.Fatal("malformed local pressure was accepted")
	}
	missing := func(string) ([]byte, error) { return []byte("some avg60=0 avg300=0 total=0 extra=0\n"), nil }
	if _, ok, err := readMemoryPressure(missing, "memory.pressure"); err == nil || ok {
		t.Fatal("pressure without avg10 was accepted")
	}
}

func TestDeltaRequiresSameSourceValidMonotonicCounters(t *testing.T) {
	trueValue := true
	finalMetric := model.CgroupV2{Available: true, Path: "/a", MemoryCurrentBytes: 0, MemoryEventsSampled: &trueValue, CPUStatSampled: &trueValue}
	first := collect.Data{Snapshot: snapshot{source: "/a", oom: 100, oomKill: 20, usageUSec: 100, throttledUSec: 10, oomValid: true, cpuValid: true, metric: model.CgroupV2{Available: true, Path: "/a", MemoryEventsSampled: &trueValue, CPUStatSampled: &trueValue}}}
	last := collect.Data{Snapshot: snapshot{source: "/a", oom: 103, oomKill: 21, usageUSec: 1000100, throttledUSec: 200010, oomValid: true, cpuValid: true, metric: finalMetric}}
	got, err := (&Collector{}).Delta(first, last)
	if err != nil {
		t.Fatal(err)
	}
	if got.CgroupV2.MemoryOOMDelta != 3 || got.CgroupV2.MemoryOOMKillDelta != 1 || got.CgroupV2.CPUUsageSecondsDelta != 1 || got.CgroupV2.CPUThrottledSecondsDelta != .2 || !*got.CgroupV2.MemoryEventsSampled {
		t.Fatalf("valid deltas = %+v", got.CgroupV2)
	}
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, CgroupV2: got.CgroupV2}}
	analyze.Report(&report)
	if findingByID(report, "cgroup-oom-kill") == nil || findingByID(report, "cgroup-cpu-throttling") == nil {
		t.Fatalf("valid deltas must remain actionable: %+v", report.Findings)
	}

	finalMetric.MemoryCurrentBytes = 7
	last.Snapshot = snapshot{source: "/b", metric: finalMetric}
	got, err = (&Collector{}).Delta(first, last)
	if err == nil || got.CgroupV2.MemoryOOMDelta != 0 || got.CgroupV2.MemoryCurrentBytes != 7 || *got.CgroupV2.MemoryEventsSampled {
		t.Fatalf("source change = %+v err=%v", got.CgroupV2, err)
	}

	first.Snapshot = snapshot{source: "/a", oom: 100, oomKill: 20, usageUSec: 100, throttledUSec: 10, oomValid: false, cpuValid: false}
	last.Snapshot = snapshot{source: "/a", oom: 200, oomKill: 120, usageUSec: 300, throttledUSec: 50, oomValid: true, cpuValid: true, metric: finalMetric}
	got, err = (&Collector{}).Delta(first, last)
	if err != nil || got.CgroupV2.MemoryOOMDelta != 0 || got.CgroupV2.CPUUsageSecondsDelta != 0 || *got.CgroupV2.CPUStatSampled {
		t.Fatalf("invalid baseline = %+v err=%v", got.CgroupV2, err)
	}
	first.Snapshot = snapshot{source: "/a", oom: 10, oomKill: 10, usageUSec: 10, throttledUSec: 10, oomValid: true, cpuValid: true}
	last.Snapshot = snapshot{source: "/a", oom: 9, oomKill: 9, usageUSec: 9, throttledUSec: 9, oomValid: true, cpuValid: true, metric: finalMetric}
	got, err = (&Collector{}).Delta(first, last)
	if err != nil || got.CgroupV2.MemoryOOMDelta != 0 || got.CgroupV2.CPUUsageSecondsDelta != 0 || *got.CgroupV2.MemoryEventsSampled || *got.CgroupV2.CPUStatSampled {
		t.Fatalf("counter regression = %+v err=%v", got.CgroupV2, err)
	}
}

func findingByID(report model.Report, id string) *model.Finding {
	for i := range report.Findings {
		if report.Findings[i].ID == id {
			return &report.Findings[i]
		}
	}
	return nil
}

func TestDeltaMissingBaselinePreservesFinalGauges(t *testing.T) {
	valid := true
	last := collect.Data{Snapshot: snapshot{source: "/a", metric: model.CgroupV2{Available: true, MemoryCurrentBytes: 0, MemoryCurrentValid: &valid, MemoryEventsSampled: &valid, CPUStatSampled: &valid}}, CgroupV2: &model.CgroupV2{Available: true, MemoryCurrentBytes: 0, MemoryCurrentValid: &valid}}
	got, err := (&Collector{}).Delta(collect.Data{}, last)
	if err == nil || got.CgroupV2 == nil || got.CgroupV2.MemoryCurrentBytes != 0 || got.CgroupV2.MemoryEventsSampled == nil || *got.CgroupV2.MemoryEventsSampled {
		t.Fatalf("missing baseline = %+v err=%v", got.CgroupV2, err)
	}
}

func TestDeltaMissingFinalIsUnavailable(t *testing.T) {
	got, err := (&Collector{}).Delta(collect.Data{Snapshot: snapshot{source: "/a"}}, collect.Data{})
	if err == nil || got.CgroupV2 == nil || got.CgroupV2.Available {
		t.Fatalf("missing final = %+v err=%v", got.CgroupV2, err)
	}
}

type fakeInfo struct{}

func (fakeInfo) Name() string       { return "cgroup.controllers" }
func (fakeInfo) Size() int64        { return 0 }
func (fakeInfo) Mode() os.FileMode  { return 0 }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (fakeInfo) IsDir() bool        { return false }
func (fakeInfo) Sys() any           { return nil }
