// Package timesync collects optional clock synchronization facts.
package timesync

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/command"
	"github.com/elcool0r/glimpse/internal/model"
)

const commandTimeout = 3 * time.Second

type Collector struct {
	Timeout  time.Duration
	lookPath func(string) (string, error)
	run      func(context.Context, string, ...string) ([]byte, error)
	readFile func(string) ([]byte, error)
}

func New() *Collector {
	return &Collector{lookPath: exec.LookPath, run: runCommand, readFile: os.ReadFile}
}
func (c *Collector) Name() string { return "time-sync" }

// Static marks clock synchronization state as a gauge.
func (c *Collector) Static() {}

func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	lookup := c.lookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	run := c.run
	if run == nil {
		run = runCommand
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = commandTimeout
	}
	if path, err := lookup("timedatectl"); err == nil {
		ctx, cancel := context.WithTimeout(parent, timeout)
		raw, err := run(ctx, path, "show", "--property=NTPSynchronized", "--property=SystemClockSynchronized", "--property=NTP", "--property=NTPSyncActive")
		cancel()
		if err == nil {
			return collect.Data{TimeSync: ParseTimedatectl(string(raw))}, nil
		}
		if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		}
	}
	if path, err := lookup("chronyc"); err == nil {
		ctx, cancel := context.WithTimeout(parent, timeout)
		raw, err := run(ctx, path, "tracking")
		cancel()
		if err == nil {
			return collect.Data{TimeSync: ParseChronyc(string(raw))}, nil
		}
		if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		}
	}
	// This rootless timesyncd marker is intentionally a last fallback: it only
	// asserts sync after timesyncd itself has created the marker.
	readFile := c.readFile
	if readFile == nil {
		readFile = os.ReadFile
	}
	if _, err := readFile("/run/systemd/timesync/synchronized"); err == nil {
		value := true
		return collect.Data{TimeSync: &model.TimeSync{Available: true, Service: "systemd-timesyncd", Synchronized: &value}}, nil
	}
	return collect.Data{TimeSync: &model.TimeSync{Available: false}, Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "no accessible time synchronization source"}}}, nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return command.Output(ctx, name, args...)
}

// ParseTimedatectl parses the stable key=value form from timedatectl show.
func ParseTimedatectl(raw string) *model.TimeSync {
	values := keyValues(raw)
	synced, hasSynced := boolValue(firstNonEmpty(values["SystemClockSynchronized"], values["NTPSynchronized"]))
	enabled, hasEnabled := boolValue(firstNonEmpty(values["NTP"], values["NTPSyncActive"]))
	result := &model.TimeSync{Available: true, Service: "systemd-timesyncd"}
	if hasSynced {
		result.Synchronized = &synced
	}
	if hasEnabled {
		result.NTPEnabled = &enabled
	}
	return result
}

// ParseChronyc extracts the tracking state without relying on locale-sensitive
// prose beyond chrony's stable field labels.
func ParseChronyc(raw string) *model.TimeSync {
	values := keyValues(raw)
	result := &model.TimeSync{Available: true, Service: "chrony"}
	if stratum, err := strconv.Atoi(strings.TrimSpace(values["Stratum"])); err == nil {
		result.Stratum = stratum
	}
	if offset, ok := parseSeconds(values["Last offset"]); ok {
		millis := offset * 1000
		result.OffsetMillis = &millis
	}
	if leap := strings.ToLower(values["Leap status"]); leap != "" {
		synced := !strings.Contains(leap, "not synchronised") && !strings.Contains(leap, "not synchronized")
		result.Synchronized = &synced
	}
	return result
}

func keyValues(raw string) map[string]string {
	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if key, value, ok := strings.Cut(line, "="); ok {
			result[strings.TrimSpace(key)] = strings.TrimSpace(value)
			continue
		}
		if key, value, ok := strings.Cut(line, ":"); ok {
			result[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return result
}

func boolValue(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "yes", "true", "1":
		return true, true
	case "no", "false", "0":
		return false, true
	default:
		return false, false
	}
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
func parseSeconds(raw string) (float64, bool) {
	value := strings.Fields(strings.TrimSpace(raw))
	if len(value) == 0 {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(strings.TrimPrefix(value[0], "+"), 64)
	if err != nil {
		return 0, false
	}
	if strings.Contains(raw, "ms") {
		return parsed / 1000, true
	}
	if strings.Contains(raw, "us") || strings.Contains(raw, "µs") {
		return parsed / 1e6, true
	}
	if strings.Contains(raw, "ns") {
		return parsed / 1e9, true
	}
	if !strings.Contains(raw, "seconds") && !strings.Contains(raw, "second") {
		return 0, false
	}
	return parsed, true
}
