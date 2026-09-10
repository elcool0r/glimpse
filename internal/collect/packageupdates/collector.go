// Package packageupdates checks local package-manager metadata for pending
// upgrades. It never refreshes metadata and never changes installed state.
package packageupdates

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/command"
	"github.com/elcool0r/glimpse/internal/model"
)

type runFunc func(context.Context, string, ...string) ([]byte, error)
type lookPathFunc func(string) (string, error)

type Collector struct {
	lookPath lookPathFunc
	run      runFunc
}

func New() *Collector {
	return &Collector{lookPath: exec.LookPath, run: command.Output}
}

func (Collector) Name() string { return "package-updates" }
func (Collector) Static()      {}

func (c Collector) Collect(ctx context.Context) (collect.Data, error) {
	lookPath := c.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	run := c.run
	if run == nil {
		run = command.Output
	}

	// apt-get is the remote-aware frontend for dpkg-managed systems. Do not
	// use dpkg-query here: it can list installed packages, not pending updates.
	for _, candidate := range []struct {
		name   string
		args   []string
		parser func(string) int
	}{{"apt-get", []string{"-s", "-q", "upgrade"}, ParseAPT}, {"dnf", []string{"check-update"}, ParseDNF}, {"yum", []string{"check-update"}, ParseYUM}} {
		if _, err := lookPath(candidate.name); err != nil {
			continue
		}
		output, err := run(ctx, candidate.name, candidate.args...)
		// dnf/yum use exit status 100 to mean updates are available. Their
		// output is still valid evidence, so parse it before handling errors.
		count := candidate.parser(string(output))
		if err == nil || count > 0 {
			return collect.Data{PackageUpdates: &model.PackageUpdates{Available: true, Manager: candidate.name, Count: count}}, nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return collect.Data{}, err
		}
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: candidate.name + ": " + err.Error()}}}, nil
	}
	return collect.Data{}, nil
}

func ParseAPT(output string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Inst ") {
			count++
		}
	}
	return count
}

// DNF and yum print one package per non-indented table row after a header.
// Requiring four fields avoids counting metadata and summary lines while
// accepting both the traditional and modern package table layouts.
func ParseDNF(output string) int { return parseRPMTable(output) }
func ParseYUM(output string) int { return parseRPMTable(output) }

func parseRPMTable(output string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) < 4 || strings.HasPrefix(trimmed, "Last metadata") || strings.HasPrefix(trimmed, "Obsoleting") {
			continue
		}
		if fields[0] == "Package" || fields[0] == "Name" || strings.HasSuffix(fields[0], ":") {
			continue
		}
		if strings.Contains(trimmed, "packages marked") || strings.Contains(trimmed, "packages available") {
			continue
		}
		count++
	}
	return count
}
