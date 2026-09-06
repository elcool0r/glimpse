// Package zfs collects optional ZFS pool status through zpool.
package zfs

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/command"
	"github.com/elcool0r/glimpse/internal/model"
)

const commandTimeout = 5 * time.Second

type Collector struct {
	Timeout  time.Duration
	lookPath func(string) (string, error)
	run      func(context.Context, string, ...string) ([]byte, error)
	inUse    func() bool
}

func New() *Collector             { return &Collector{lookPath: exec.LookPath, run: runCommand} }
func (c *Collector) Name() string { return "zfs" }

// Static marks pool status as a gauge; its counters are pool lifetime values,
// not sampled deltas, so a baseline zpool invocation buys nothing.
func (c *Collector) Static() {}
func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	if !c.zfsInUse() {
		return collect.Data{}, nil
	}
	lookup := c.lookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	path, err := lookup("zpool")
	if err != nil {
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: err.Error()}}}, nil
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = commandTimeout
	}
	run := c.run
	if run == nil {
		run = runCommand
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	raw, err := run(ctx, path, "status", "-P")
	if err != nil {
		if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		}
		// zpool can return a non-zero status for an unhealthy pool. Keep stdout
		// in that case: the state and scan details are exactly what the report
		// needs, and throwing them away would hide the incident.
		pools := ParseStatus(string(raw))
		if len(pools) == 0 {
			return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: err.Error()}}}, nil
		}
		return collect.Data{ZFSPools: pools, Diagnostics: []model.CollectionStatus{{Status: "error", Detail: fmt.Sprintf("zpool status exited with an error: %v", err)}}}, nil
	}
	pools := ParseStatus(string(raw))
	if pools == nil {
		pools = []model.ZFSPool{}
	}
	return collect.Data{ZFSPools: pools}, nil
}

func (c *Collector) zfsInUse() bool {
	if c.inUse != nil {
		return c.inUse()
	}
	if _, err := os.Stat("/sys/module/zfs"); err == nil {
		return true
	}
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, " - zfs ") {
			return true
		}
	}
	return false
}

// ParseStatus handles zpool's human-readable status output conservatively.
// It only uses the root pool row for counters; leaf vdev counters are not
// summed because mirrors and raidz would otherwise double-count failures.
func ParseStatus(text string) []model.ZFSPool {
	var pools []model.ZFSPool
	var current *model.ZFSPool
	inConfig := false
	inScan := false
	finish := func() {
		if current != nil {
			pools = append(pools, *current)
			current = nil
			inConfig = false
			inScan = false
		}
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "pool:") {
			finish()
			name := strings.TrimSpace(strings.TrimPrefix(line, "pool:"))
			if name != "" {
				current = &model.ZFSPool{Name: name}
			}
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "state:") {
			current.Health = strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "state:")))
			continue
		}
		if strings.HasPrefix(line, "scan:") {
			current.ScanState = strings.TrimSpace(strings.TrimPrefix(line, "scan:"))
			inScan = true
			continue
		}
		if inScan && line != "" {
			// Scan progress spans several indented lines. A new labeled field
			// terminates it; bound retained text independently of command output.
			if strings.HasPrefix(line, "config:") || strings.HasPrefix(line, "errors:") || strings.HasPrefix(line, "remove:") || strings.HasPrefix(line, "checkpoint:") || strings.HasPrefix(line, "expand:") || strings.HasPrefix(line, "action:") || strings.HasPrefix(line, "status:") {
				inScan = false
			} else if !strings.HasPrefix(line, "config:") && len(current.ScanState)+len(line) < 2048 {
				current.ScanState += " " + line
				continue
			}
		}
		if strings.HasPrefix(line, "config:") {
			inConfig = true
			continue
		}
		if strings.HasPrefix(line, "errors:") {
			detail := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "errors:")))
			current.PermanentErrors = detail != "" && !strings.Contains(detail, "no known data errors")
			inConfig = false
			continue
		}
		if inConfig {
			f := strings.Fields(line)
			if len(f) >= 5 && f[0] == current.Name && isState(f[1]) {
				current.ReadErrors = parseUint(f[2])
				current.WriteErrors = parseUint(f[3])
				current.ChecksumErrors = parseUint(f[4])
			}
		}
	}
	finish()
	sort.Slice(pools, func(i, j int) bool { return pools[i].Name < pools[j].Name })
	return pools
}
func isState(s string) bool {
	switch strings.ToUpper(s) {
	case "ONLINE", "DEGRADED", "FAULTED", "OFFLINE", "REMOVED", "UNAVAIL", "SUSPENDED":
		return true
	}
	return false
}
func parseUint(s string) uint64 { v, _ := strconv.ParseUint(s, 10, 64); return v }
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return command.Output(ctx, name, args...)
}
