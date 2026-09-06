// Package systemd collects failed unit names through systemctl when it is
// available. It is intentionally optional: containers and non-systemd hosts
// commonly do not expose a usable system bus.
package systemd

import (
	"context"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/command"
	"github.com/elcool0r/glimpse/internal/model"
)

const commandTimeout = 3 * time.Second

// Collector collects current failed systemd units. Timeout is configurable for
// tests; a zero value uses the conservative default.
type Collector struct {
	Timeout  time.Duration
	lookPath func(string) (string, error)
	run      func(context.Context, string, ...string) ([]byte, error)
}

func New() *Collector {
	return &Collector{lookPath: exec.LookPath, run: runCommand}
}

func (c *Collector) Name() string { return "systemd" }

// Static marks failed-unit state as a gauge: only the final observation is used.
func (c *Collector) Static() {}

func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	lookup := c.lookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	path, err := lookup("systemctl")
	if err != nil {
		return collect.Data{Systemd: &model.Systemd{Available: false}, Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: err.Error()}}}, nil
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
	output, err := run(ctx, path, "--failed", "--no-legend", "--plain", "--no-pager")
	// A disconnected user/container bus is an unavailable capability, not a
	// health error. Context cancellation remains meaningful to the caller.
	if err != nil {
		if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		}
		return collect.Data{Systemd: &model.Systemd{Available: false}, Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: err.Error()}}}, nil
	}
	return collect.Data{Systemd: &model.Systemd{Available: true, FailedUnits: ParseFailedUnits(string(output))}}, nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return command.Output(ctx, name, args...)
}

// ParseFailedUnits parses the stable first column of `systemctl --failed`
// output. Decorative headings and an empty result are ignored.
func ParseFailedUnits(output string) []string {
	units := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.Contains(fields[0], ".") {
			continue
		}
		if fields[1] != "loaded" {
			continue
		}
		if _, exists := seen[fields[0]]; exists {
			continue
		}
		seen[fields[0]] = struct{}{}
		units = append(units, fields[0])
	}
	sort.Strings(units)
	return units
}
