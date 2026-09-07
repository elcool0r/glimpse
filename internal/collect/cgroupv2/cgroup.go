// Package cgroupv2 collects limits and sampled events for glimpse's cgroup.
package cgroupv2

import (
	"bufio"
	"context"
	"errors"
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
	oom, oomKill, usageUSec, throttledUSec uint64
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
	s := snapshot{metric: model.CgroupV2{Available: true, Path: path, Containerized: isContainerized(path)}}
	s.metric.MemoryCurrentBytes = readUint(read, filepath.Join(dir, "memory.current"))
	s.metric.MemoryMaxBytes = readLimit(read, filepath.Join(dir, "memory.max"))
	s.metric.MemorySwapCurrentBytes = readUint(read, filepath.Join(dir, "memory.swap.current"))
	s.metric.MemorySwapMaxBytes = readLimit(read, filepath.Join(dir, "memory.swap.max"))
	s.metric.PIDsCurrent = readUint(read, filepath.Join(dir, "pids.current"))
	s.metric.PIDsMax = readLimit(read, filepath.Join(dir, "pids.max"))
	memEvents := ParseKeyValues(readText(read, filepath.Join(dir, "memory.events")))
	s.oom, s.oomKill = memEvents["oom"], memEvents["oom_kill"]
	cpuStat := ParseKeyValues(readText(read, filepath.Join(dir, "cpu.stat")))
	s.usageUSec, s.throttledUSec = cpuStat["usage_usec"], cpuStat["throttled_usec"]
	return collect.Data{CgroupV2: &s.metric, Snapshot: s}, nil
}

func (c *Collector) Delta(first, last collect.Data) (collect.Data, error) {
	a, aok := first.Snapshot.(snapshot)
	b, bok := last.Snapshot.(snapshot)
	if !aok || !bok {
		return last, nil
	}
	m := b.metric
	m.MemoryOOMDelta = counterDelta(a.oom, b.oom)
	m.MemoryOOMKillDelta = counterDelta(a.oomKill, b.oomKill)
	m.CPUUsageSecondsDelta = float64(counterDelta(a.usageUSec, b.usageUSec)) / 1e6
	m.CPUThrottledSecondsDelta = float64(counterDelta(a.throttledUSec, b.throttledUSec)) / 1e6
	return collect.Data{CgroupV2: &m}, nil
}

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
func readText(read func(string) ([]byte, error), name string) string {
	b, e := read(name)
	if e != nil {
		return ""
	}
	return string(b)
}
func readUint(read func(string) ([]byte, error), name string) uint64 {
	v := ParseKeyValues("x " + strings.TrimSpace(readText(read, name)))
	return v["x"]
}
func readLimit(read func(string) ([]byte, error), name string) *uint64 {
	text := strings.TrimSpace(readText(read, name))
	if text == "" || text == "max" {
		return nil
	}
	v, e := strconv.ParseUint(text, 10, 64)
	if e != nil {
		return nil
	}
	return &v
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
