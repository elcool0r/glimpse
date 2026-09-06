// Package kernel performs a deliberately bounded scan for a few high-signal
// kernel failure patterns. It never treats a generic "error" log line as a
// health event.
package kernel

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/command"
	"github.com/elcool0r/glimpse/internal/model"
)

const (
	commandTimeout = 4 * time.Second
	maxLines       = 200
)

type Collector struct {
	Timeout  time.Duration
	lookPath func(string) (string, error)
	run      func(context.Context, string, ...string) ([]byte, error)
}

func New() *Collector             { return &Collector{lookPath: exec.LookPath, run: runCommand} }
func (c *Collector) Name() string { return "kernel" }

// Static marks the journal scan as a gauge: the same records are returned at
// both boundaries, so scanning twice only doubles the journalctl cost.
func (c *Collector) Static() {}

func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	lookup := c.lookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	path, err := lookup("journalctl")
	if err != nil {
		return collect.Data{Kernel: &model.Kernel{Available: false}, Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: err.Error()}}}, nil
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = commandTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	run := c.run
	if run == nil {
		run = runCommand
	}
	// Boot scope prevents old incidents from appearing current; the time bound
	// also handles unusually long-lived hosts. -n bounds journal records.
	// short-unix retains the record timestamp, which is what lets analysis
	// distinguish an incident happening now from one recorded overnight.
	output, err := run(ctx, path, "--boot=0", "--since=-24h", "-k", "--priority=warning", "--no-pager", "--output=short-unix", "--lines=200")
	if err != nil {
		if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		}
		return collect.Data{Kernel: &model.Kernel{Available: false}, Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: err.Error()}}}, nil
	}
	return collect.Data{Kernel: &model.Kernel{Available: true, Events: ParseEvents(string(output), time.Now())}}, nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return command.Output(ctx, name, args...)
}

// ParseEvents detects only explicit, actionable kernel failure signatures.
// It keeps one event per matching line and caps parsing defensively even if a
// journal implementation ignores --lines.
//
// now is the reference for record age. Records carrying a journal timestamp
// report their age so analysis can weigh a current incident differently from
// one recorded hours ago; records without one leave the age unknown.
func ParseEvents(output string, now time.Time) []model.LogEvent {
	events := make([]model.LogEvent, 0)
	seen := make(map[string]struct{})
	for index, raw := range strings.Split(output, "\n") {
		if index >= maxLines {
			break
		}
		line, age := splitTimestamp(strings.TrimSpace(raw), now)
		if line == "" {
			continue
		}
		if kind := eventKind(line); kind != "" {
			// A single kernel incident commonly produces several matching log
			// records. Keep concise, non-duplicative evidence so one event does
			// not dominate the report or score.
			key := kind
			if kind == "oom" || kind == "cgroup_oom" {
				key = "oom"
			}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			events = append(events, model.LogEvent{Kind: kind, Message: line, AgeSeconds: age})
		}
	}
	return events
}

// splitTimestamp removes journalctl's short-unix prefix
// ("<epoch> <host> <identifier>[<pid>]: <message>") and returns the message
// with its age. Output without a leading timestamp — the older --output=cat
// form, or any other producer — is returned unchanged with an unknown age.
func splitTimestamp(line string, now time.Time) (string, *float64) {
	stamp, rest, ok := strings.Cut(line, " ")
	if !ok {
		return line, nil
	}
	seconds, err := strconv.ParseFloat(stamp, 64)
	if err != nil || seconds <= 0 {
		return line, nil
	}
	age := now.Sub(time.Unix(int64(seconds), 0)).Seconds()
	if age < 0 {
		age = 0
	}
	// Drop "<host> <identifier>[<pid>]: " so the retained message is the
	// kernel text itself, matching what the previous --output=cat form gave.
	if _, message, found := strings.Cut(rest, ": "); found {
		rest = message
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", nil
	}
	return rest, &age
}

func eventKind(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "memory cgroup out of memory") || strings.Contains(lower, "cgroup out of memory"):
		return "cgroup_oom"
	case strings.Contains(lower, "out of memory") || strings.Contains(lower, "oom-killer") || strings.Contains(lower, "killed process"):
		return "oom"
	case strings.Contains(lower, "kernel panic"):
		return "kernel_panic"
	case strings.Contains(lower, "kernel oops") || strings.Contains(lower, "oops:") || strings.Contains(lower, "unable to handle kernel"):
		return "kernel_oops"
	case strings.Contains(lower, "blocked for more than") || strings.Contains(lower, "task hung"):
		return "blocked_task"
	case strings.Contains(lower, "nvme") && (strings.Contains(lower, "reset") || strings.Contains(lower, "i/o error") || strings.Contains(lower, "timeout")):
		return "nvme_error"
	case strings.Contains(lower, "i/o error") || strings.Contains(lower, "buffer i/o error") || strings.Contains(lower, "blk_update_request"):
		return "io_error"
	case strings.Contains(lower, "xfs") && strings.Contains(lower, "corruption"):
		return "filesystem_corruption"
	case strings.Contains(lower, "ext4-fs error") || strings.Contains(lower, "btrfs error"):
		return "filesystem_error"
	case strings.Contains(lower, "machine check") || strings.Contains(lower, "hardware error"):
		return "hardware_error"
	case strings.Contains(lower, "zfs") && (strings.Contains(lower, "error") || strings.Contains(lower, "fault") || strings.Contains(lower, "degrad")):
		return "zfs_error"
	case strings.Contains(lower, "thermal") && (strings.Contains(lower, "throttl") || strings.Contains(lower, "critical")):
		return "thermal_throttling"
	default:
		return ""
	}
}
