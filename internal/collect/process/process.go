// Package process samples process state and top CPU/RSS consumers from procfs.
package process

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Process struct {
	PID            int
	ParentPID      int
	Name           string
	State          byte
	CPUTimeTicks   uint64
	RSSBytes       uint64
	Threads        uint64
	StartTimeTicks uint64
	CPUFraction    float64
	CPUAvailable   bool
}
type Snapshot struct {
	Processes         int
	Running           int
	Sleeping          int
	Blocked           int
	Zombies           int
	TopCPU            []Process
	TopRSS            []Process
	TotalCPUTicks     uint64
	CPUTicksAvailable bool
	CPUCount          int
	all               []Process
}

// ParseStat parses /proc/<pid>/stat. It supports comm values containing spaces or parentheses.
func ParseStat(s string, pageSize int64) (Process, error) {
	open := strings.IndexByte(s, '(')
	close := strings.LastIndexByte(s, ')')
	if open < 1 || close <= open || close+2 >= len(s) {
		return Process{}, fmt.Errorf("invalid proc stat")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(s[:open]))
	if err != nil {
		return Process{}, fmt.Errorf("pid: %w", err)
	}
	rest := strings.Fields(s[close+1:])
	if len(rest) < 22 {
		return Process{}, fmt.Errorf("proc stat has %d fields after comm", len(rest))
	}
	state := rest[0]
	if len(state) != 1 {
		return Process{}, fmt.Errorf("invalid state")
	}
	parentPID, err := strconv.Atoi(rest[1])
	if err != nil {
		return Process{}, fmt.Errorf("parent pid: %w", err)
	}
	utime, err := strconv.ParseUint(rest[11], 10, 64)
	if err != nil {
		return Process{}, err
	}
	stime, err := strconv.ParseUint(rest[12], 10, 64)
	if err != nil {
		return Process{}, err
	}
	threads, err := strconv.ParseUint(rest[17], 10, 64)
	if err != nil {
		return Process{}, err
	}
	rssPages, err := strconv.ParseInt(rest[21], 10, 64)
	if err != nil {
		return Process{}, err
	}
	if rssPages < 0 {
		rssPages = 0
	}
	startTime, err := strconv.ParseUint(rest[19], 10, 64)
	if err != nil {
		return Process{}, err
	}
	return Process{PID: pid, ParentPID: parentPID, Name: s[open+1 : close], State: state[0], CPUTimeTicks: utime + stime, RSSBytes: uint64(rssPages * pageSize), Threads: threads, StartTimeTicks: startTime}, nil
}

func ParseStatReader(r io.Reader, pageSize int64) (Process, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return Process{}, err
	}
	return ParseStat(strings.TrimSpace(string(b)), pageSize)
}

func Collect(ctx context.Context, procRoot string, limit int) (Snapshot, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if limit <= 0 {
		limit = 10
	}
	dirs, err := os.ReadDir(procRoot)
	if err != nil {
		return Snapshot{}, err
	}
	pageSize := int64(os.Getpagesize())
	var all []Process
	summary := Snapshot{}
	if raw, err := os.ReadFile(filepath.Join(procRoot, "stat")); err == nil {
		summary.TotalCPUTicks, err = ParseCPUTicks(string(raw))
		summary.CPUTicksAvailable = err == nil
		summary.CPUCount = CountCPUs(string(raw))
	}
	for _, dir := range dirs {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		pid, err := strconv.Atoi(dir.Name())
		if err != nil || pid < 1 {
			continue
		}
		f, err := os.Open(filepath.Join(procRoot, dir.Name(), "stat"))
		if err != nil {
			continue
		}
		p, parseErr := ParseStatReader(f, pageSize)
		f.Close()
		if parseErr != nil {
			continue
		}
		summary.Processes++
		switch p.State {
		case 'R':
			summary.Running++
		case 'D':
			summary.Blocked++
		case 'Z':
			summary.Zombies++
		case 'S', 'I':
			summary.Sleeping++
		}
		all = append(all, p)
	}
	summary.TopCPU = top(all, limit, func(p Process) uint64 { return p.CPUTimeTicks })
	summary.TopRSS = top(all, limit, func(p Process) uint64 { return p.RSSBytes })
	summary.all = all
	return summary, nil
}

// ParseCPUTicks returns aggregate CPU ticks from the first "cpu" line in
// /proc/stat. Guest fields are excluded because Linux already includes them
// in user and nice; including them would double count guest time.
func ParseCPUTicks(text string) (uint64, error) {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 || fields[0] != "cpu" {
			continue
		}
		var total uint64
		for _, field := range fields[1:9] {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("cpu ticks: %w", err)
			}
			total += value
		}
		return total, nil
	}
	return 0, fmt.Errorf("aggregate cpu line missing")
}

// CountCPUs counts logical CPU rows (cpu0, cpu1, ...) in /proc/stat.
func CountCPUs(text string) int {
	count := 0
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "cpu" || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimPrefix(fields[0], "cpu")); err == nil {
			count++
		}
	}
	return count
}

func top(all []Process, limit int, key func(Process) uint64) []Process {
	result := append([]Process(nil), all...)
	sort.Slice(result, func(i, j int) bool {
		a, b := key(result[i]), key(result[j])
		if a == b {
			return result[i].PID < result[j].PID
		}
		return a > b
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}
