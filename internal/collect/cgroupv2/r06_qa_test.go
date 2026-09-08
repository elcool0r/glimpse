package cgroupv2

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/model"
)

// The R06 trigger was a failed baseline read followed by a readable lifetime
// counter. Exercise the collector boundary contract through analysis and JSON
// so neither layer can turn that historical counter into a current incident.
func TestR06UnreadableBaselineDoesNotCreateHistoricalOOMFinding(t *testing.T) {
	files := map[string]string{
		"/proc/self/cgroup":                          "0::/slice/a\n",
		"/sys/fs/cgroup/cgroup.controllers":          "memory pids cpu\n",
		"/sys/fs/cgroup/slice/a/memory.current":      "99",
		"/sys/fs/cgroup/slice/a/memory.max":          "100",
		"/sys/fs/cgroup/slice/a/memory.swap.current": "0",
		"/sys/fs/cgroup/slice/a/memory.swap.max":     "max",
		"/sys/fs/cgroup/slice/a/pids.current":        "1",
		"/sys/fs/cgroup/slice/a/pids.max":            "max",
		"/sys/fs/cgroup/slice/a/memory.events":       "oom 100\noom_kill 100\n",
		"/sys/fs/cgroup/slice/a/cpu.stat":            "usage_usec 100\nthrottled_usec 50\n",
	}
	baseline := true
	read := func(name string) ([]byte, error) {
		if baseline && strings.HasSuffix(name, "/memory.events") {
			return nil, errors.New("permission denied")
		}
		value, ok := files[name]
		if !ok {
			return nil, errors.New("missing fixture")
		}
		return []byte(value), nil
	}
	c := &Collector{
		ProcRoot: "/proc", CgroupRoot: "/sys/fs/cgroup", readFile: read,
		stat: func(string) (os.FileInfo, error) { return fakeInfo{}, nil },
	}
	first, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	baseline = false
	last, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	delta, err := c.Delta(first, last)
	if err != nil {
		t.Fatal(err)
	}
	if delta.CgroupV2.MemoryEventsSampled == nil || *delta.CgroupV2.MemoryEventsSampled {
		t.Fatalf("memory events must be explicitly unsampled: %+v", delta.CgroupV2)
	}
	if delta.CgroupV2.MemoryCurrentBytes != 99 || delta.CgroupV2.MemoryMaxBytes == nil || *delta.CgroupV2.MemoryMaxBytes != 100 {
		t.Fatalf("valid final gauges were lost: %+v", delta.CgroupV2)
	}

	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, CgroupV2: delta.CgroupV2}}
	analyze.Report(&report)
	for _, finding := range report.Findings {
		if finding.ID == "cgroup-oom" || finding.ID == "cgroup-oom-kill" || finding.ID == "cgroup-memory-limit" {
			t.Fatalf("historical counter created a finding: %+v", finding)
		}
	}
	encoded, err := json.Marshal(delta.CgroupV2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"memory_events_sampled":false`) {
		t.Fatalf("JSON did not expose invalid sampled counter state: %s", encoded)
	}
}
