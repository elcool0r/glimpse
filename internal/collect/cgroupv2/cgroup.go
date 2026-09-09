// Package cgroupv2 collects limits and sampled events for glimpse's cgroup.
package cgroupv2

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

// Collector reads only the cgroup containing the current process.  Missing
// controllers are normal on older, delegated, and containerized hosts.
type Collector struct {
	ProcRoot   string
	CgroupRoot string
	readFile   func(string) ([]byte, error)
	stat       func(string) (os.FileInfo, error)
}

func New() *Collector             { return &Collector{readFile: os.ReadFile, stat: os.Stat} }
func (c *Collector) Name() string { return "cgroup-v2" }

type snapshot struct {
	metric                                 model.CgroupV2
	source                                 string
	oom, oomKill, usageUSec, throttledUSec uint64
	oomValid, cpuValid                     bool
}

func (c *Collector) Collect(ctx context.Context) (collect.Data, error) {
	if err := ctx.Err(); err != nil {
		return collect.Data{}, err
	}
	read := c.readFile
	if read == nil {
		read = os.ReadFile
	}
	stat := c.stat
	if stat == nil {
		stat = os.Stat
	}
	proc := c.ProcRoot
	if proc == "" {
		proc = "/proc"
	}
	root := c.CgroupRoot
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	if _, err := stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return collect.Data{CgroupV2: &model.CgroupV2{Available: false}}, nil
	}
	rawPath, err := read(filepath.Join(proc, "self/cgroup"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return collect.Data{CgroupV2: &model.CgroupV2{Available: false}}, nil
		}
		return collect.Data{}, err
	}
	path, ok := ParsePath(string(rawPath))
	if !ok {
		return collect.Data{CgroupV2: &model.CgroupV2{Available: false}}, nil
	}
	dir := filepath.Join(root, filepath.Clean("/"+path))
	// filepath.Join intentionally cannot escape root because path was normalized.
	s := snapshot{metric: model.CgroupV2{Available: true, Path: path, Containerized: isContainerized(path)}, source: filepath.Clean(dir)}
	var diagnostics []model.CollectionStatus
	add := func(file string, detail error) {
		diagnostics = append(diagnostics, model.CollectionStatus{Collector: c.Name(), Status: "unavailable", Detail: file + ": " + detail.Error()})
	}
	setUint := func(file string, dst *uint64, valid **bool) {
		v, ok, err := readUint(read, filepath.Join(dir, file))
		*valid = boolPtr(ok)
		if ok {
			*dst = v
		} else {
			add(file, err)
		}
	}
	setLimit := func(file string, dst **uint64, valid **bool) {
		v, ok, err := readLimit(read, filepath.Join(dir, file))
		*valid = boolPtr(ok)
		if ok {
			*dst = v
		} else {
			add(file, err)
		}
	}
	setUint("memory.current", &s.metric.MemoryCurrentBytes, &s.metric.MemoryCurrentValid)
	setLimit("memory.max", &s.metric.MemoryMaxBytes, &s.metric.MemoryMaxValid)
	setUint("memory.swap.current", &s.metric.MemorySwapCurrentBytes, &s.metric.MemorySwapCurrentValid)
	setLimit("memory.swap.max", &s.metric.MemorySwapMaxBytes, &s.metric.MemorySwapMaxValid)
	setUint("pids.current", &s.metric.PIDsCurrent, &s.metric.PIDsCurrentValid)
	setLimit("pids.max", &s.metric.PIDsMax, &s.metric.PIDsMaxValid)
	pressure, ok, err := readMemoryPressure(read, filepath.Join(dir, "memory.pressure"))
	s.metric.MemoryPressureValid = boolPtr(ok)
	if ok {
		s.metric.MemoryPressure = &pressure
	} else {
		add("memory.pressure", err)
	}
	memEvents, ok, err := readRequired(read, filepath.Join(dir, "memory.events"), "oom", "oom_kill")
	s.metric.MemoryEventsSampled = boolPtr(ok)
	if ok {
		s.oom, s.oomKill, s.oomValid = memEvents["oom"], memEvents["oom_kill"], true
	} else {
		add("memory.events", err)
	}
	cpuStat, ok, err := readRequired(read, filepath.Join(dir, "cpu.stat"), "usage_usec", "throttled_usec")
	s.metric.CPUStatSampled = boolPtr(ok)
	if ok {
		s.usageUSec, s.throttledUSec, s.cpuValid = cpuStat["usage_usec"], cpuStat["throttled_usec"], true
	} else {
		add("cpu.stat", err)
	}
	return collect.Data{CgroupV2: &s.metric, Snapshot: s, Diagnostics: diagnostics}, nil
}

func (c *Collector) Delta(first, last collect.Data) (collect.Data, error) {
	a, aok := first.Snapshot.(snapshot)
	b, bok := last.Snapshot.(snapshot)
	if !aok || !bok {
		m := finalMetric(last)
		return collect.Data{CgroupV2: m, Diagnostics: last.Diagnostics}, errors.New("cgroup-v2: missing sample boundary")
	}
	m := b.metric
	if a.source != b.source {
		setUnsampled(&m)
		return collect.Data{CgroupV2: &m, Diagnostics: last.Diagnostics}, fmt.Errorf("cgroup-v2: source path changed from %q to %q", a.source, b.source)
	}
	if a.oomValid && b.oomValid && b.oom >= a.oom && b.oomKill >= a.oomKill {
		m.MemoryOOMDelta, m.MemoryOOMKillDelta = b.oom-a.oom, b.oomKill-a.oomKill
	} else {
		m.MemoryOOMDelta, m.MemoryOOMKillDelta = 0, 0
		m.MemoryEventsSampled = boolPtr(false)
	}
	if a.cpuValid && b.cpuValid && b.usageUSec >= a.usageUSec && b.throttledUSec >= a.throttledUSec {
		m.CPUUsageSecondsDelta = float64(b.usageUSec-a.usageUSec) / 1e6
		m.CPUThrottledSecondsDelta = float64(b.throttledUSec-a.throttledUSec) / 1e6
	} else {
		m.CPUUsageSecondsDelta, m.CPUThrottledSecondsDelta = 0, 0
		m.CPUStatSampled = boolPtr(false)
	}
	return collect.Data{CgroupV2: &m, Diagnostics: last.Diagnostics}, nil
}

func finalMetric(last collect.Data) *model.CgroupV2 {
	if last.CgroupV2 == nil {
		return &model.CgroupV2{Available: false}
	}
	m := *last.CgroupV2
	setUnsampled(&m)
	return &m
}

func setUnsampled(m *model.CgroupV2) {
	zero := uint64(0)
	m.MemoryOOMDelta, m.MemoryOOMKillDelta = zero, zero
	m.CPUUsageSecondsDelta, m.CPUThrottledSecondsDelta = 0, 0
	m.MemoryEventsSampled, m.CPUStatSampled = boolPtr(false), boolPtr(false)
}

func boolPtr(v bool) *bool { return &v }

func ParsePath(text string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "0::") {
			p := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
			if strings.HasPrefix(p, "/") {
				return p, true
			}
		}
	}
	return "", false
}
func ParseKeyValues(text string) map[string]uint64 {
	out := map[string]uint64{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 {
			if v, e := strconv.ParseUint(f[1], 10, 64); e == nil {
				out[f[0]] = v
			}
		}
	}
	return out
}
func readText(read func(string) ([]byte, error), name string) (string, bool, error) {
	b, e := read(name)
	if e != nil {
		return "", false, fmt.Errorf("read failed: %v", e)
	}
	return string(b), true, nil
}
func readUint(read func(string) ([]byte, error), name string) (uint64, bool, error) {
	text, _, err := readText(read, name)
	if err != nil {
		return 0, false, err
	}
	v, err := strconv.ParseUint(strings.TrimSpace(text), 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("malformed value")
	}
	return v, true, nil
}
func readLimit(read func(string) ([]byte, error), name string) (*uint64, bool, error) {
	text, _, err := readText(read, name)
	if err != nil {
		return nil, false, err
	}
	text = strings.TrimSpace(text)
	if text == "max" {
		return nil, true, nil
	}
	v, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return nil, false, fmt.Errorf("malformed value")
	}
	return &v, true, nil
}

func readRequired(read func(string) ([]byte, error), name string, required ...string) (map[string]uint64, bool, error) {
	text, _, err := readText(read, name)
	if err != nil {
		return nil, false, err
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			if contains(required, fields[0]) {
				return nil, false, fmt.Errorf("malformed value for %s", fields[0])
			}
			continue
		}
		v, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			if contains(required, fields[0]) {
				return nil, false, fmt.Errorf("malformed value for %s", fields[0])
			}
			continue
		}
		values[fields[0]] = v
	}
	for _, key := range required {
		if _, ok := values[key]; !ok {
			return nil, false, fmt.Errorf("missing required key %s", key)
		}
	}
	return values, true, nil
}

// readMemoryPressure accepts the cgroup-v2 PSI format and retains the local
// some/full averages in the shared model representation. A missing or
// malformed local file is explicitly invalid rather than host PSI fallback.
func readMemoryPressure(read func(string) ([]byte, error), name string) (model.PressureResource, bool, error) {
	text, _, err := readText(read, name)
	if err != nil {
		return model.PressureResource{}, false, err
	}
	var out model.PressureResource
	haveSome := false
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 5 || (fields[0] != "some" && fields[0] != "full") {
			return model.PressureResource{}, false, fmt.Errorf("malformed pressure line")
		}
		var avg10 float64
		seen := map[string]bool{}
		for _, field := range fields[1:] {
			key, value, found := strings.Cut(field, "=")
			if !found {
				return model.PressureResource{}, false, fmt.Errorf("malformed pressure field")
			}
			switch key {
			case "avg10":
				if seen[key] {
					return model.PressureResource{}, false, fmt.Errorf("duplicate pressure %s", key)
				}
				avg10, err = strconv.ParseFloat(value, 64)
				if err != nil || math.IsNaN(avg10) || math.IsInf(avg10, 0) || avg10 < 0 {
					return model.PressureResource{}, false, fmt.Errorf("malformed pressure avg10")
				}
			case "avg60", "avg300":
				if seen[key] {
					return model.PressureResource{}, false, fmt.Errorf("duplicate pressure %s", key)
				}
				v, parseErr := strconv.ParseFloat(value, 64)
				if parseErr != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
					return model.PressureResource{}, false, fmt.Errorf("malformed pressure %s", key)
				}
			case "total":
				if seen[key] {
					return model.PressureResource{}, false, fmt.Errorf("duplicate pressure %s", key)
				}
				if _, parseErr := strconv.ParseUint(value, 10, 64); parseErr != nil {
					return model.PressureResource{}, false, fmt.Errorf("malformed pressure total")
				}
			default:
				return model.PressureResource{}, false, fmt.Errorf("unknown pressure field %s", key)
			}
			seen[key] = true
		}
		if !seen["avg10"] || !seen["avg60"] || !seen["avg300"] || !seen["total"] {
			return model.PressureResource{}, false, fmt.Errorf("missing pressure field")
		}
		if fields[0] == "some" {
			out.SomeAvg10, haveSome = avg10, true
		} else {
			out.FullAvg10 = avg10
		}
	}
	if !haveSome {
		return model.PressureResource{}, false, fmt.Errorf("missing pressure some line")
	}
	return out, true, nil
}
func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
func counterDelta(before, after uint64) uint64 {
	if after < before {
		return 0
	}
	return after - before
}
func isContainerized(path string) bool {
	path = strings.ToLower(path)
	if strings.Contains(path, "docker") || strings.Contains(path, "kubepods") || strings.Contains(path, "libpod") || strings.Contains(path, "containerd") || strings.Contains(path, "lxc") {
		return true
	}
	// systemd-nspawn units live below machine.slice as machine-<name>.scope.
	// Restrict this match to that exact hierarchy so an unrelated user-created
	// scope named machine-* is not described as a container.
	if strings.Contains(path, "/machine.slice/machine-") && strings.HasSuffix(path, ".scope") {
		return true
	}
	_, d := os.Stat("/.dockerenv")
	_, p := os.Stat("/run/.containerenv")
	return d == nil || p == nil
}
