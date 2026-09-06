// Package security collects small, read-only Linux security and maintenance facts.
package security

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/command"
	"github.com/elcool0r/glimpse/internal/model"
)

const maxCommandOutput = 256 << 10

// journalWindow bounds the auth and denial counts to a stated interval.
//
// The previous query asked for the last 300 records of the whole journal and
// counted matches within them. On a busy host those records are whatever
// happened in the last few seconds, so a real authentication attack could
// score zero while a quiet host scored high: the number had no denominator
// and two runs on one host could disagree. Filtering at the source gives the
// count a defined window and a defined population.
const (
	journalWindow      = "1h"
	journalWindowLabel = "the last hour"
	journalMaxRecords  = "5000"
	// authprivFacility selects syslog authpriv, where sshd, sudo and PAM
	// record authentication outcomes. Priority cannot be used instead: these
	// records are informational, not warnings.
	authprivFacility = "SYSLOG_FACILITY=10"
)

type Collector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	lookPath func(string) (string, error)
	run      func(context.Context, string, ...string) ([]byte, error)
	Timeout  time.Duration
}

func New() *Collector {
	return &Collector{readFile: os.ReadFile, readDir: os.ReadDir, lookPath: exec.LookPath, run: runCommand}
}
func (c *Collector) Name() string { return "security" }

// Static marks these observations as gauges: markers, policy state and bounded
// journal counts are read once for the report, not sampled across the window.
func (c *Collector) Static() {}

func (c *Collector) Collect(ctx context.Context) (collect.Data, error) {
	if err := ctx.Err(); err != nil {
		return collect.Data{}, err
	}
	readFile, readDir := c.readFile, c.readDir
	if readFile == nil {
		readFile = os.ReadFile
	}
	if readDir == nil {
		readDir = os.ReadDir
	}
	s := &model.Security{SELinux: "unknown", AppArmor: "unknown"}
	observed := false
	var diagnostics []model.CollectionStatus
	if _, err := readFile("/var/run/reboot-required"); err == nil {
		v := true
		s.RebootRequired = &v
		if _, packageErr := readFile("/var/run/reboot-required.pkgs"); packageErr == nil {
			s.RebootFromPackages = true
		}
		observed = true
	} else if errors.Is(err, os.ErrNotExist) {
		// This marker is Debian-family specific. Its absence means only that
		// this source did not request a reboot, not that no reboot is needed.
	} else {
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "reboot marker: " + err.Error()})
	}
	if raw, err := readFile("/proc/sys/kernel/tainted"); err == nil {
		mask, parseErr := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if parseErr == nil {
			s.KernelTaintMask = mask
			v := mask != 0
			s.KernelTainted = &v
			observed = true
		} else {
			diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "kernel taint: " + parseErr.Error()})
		}
	} else {
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "kernel taint: " + err.Error()})
	}
	if s.KernelTaintMask != 0 {
		if raw, err := readFile("/proc/modules"); err == nil {
			s.KernelTaintModules = taintedModuleNames(readFile, string(raw))
		}
	}
	if raw, err := readFile("/sys/fs/selinux/enforce"); err == nil {
		switch strings.TrimSpace(string(raw)) {
		case "1":
			s.SELinux = "enforcing"
			observed = true
		case "0":
			s.SELinux = "permissive"
			observed = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "SELinux: " + err.Error()})
	}
	if raw, err := readFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		switch strings.ToLower(strings.TrimSpace(string(raw))) {
		case "y", "yes", "1":
			s.AppArmor = "enabled"
			observed = true
		case "n", "no", "0":
			s.AppArmor = "disabled"
			observed = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "AppArmor: " + err.Error()})
	}
	vulnDir := "/sys/devices/system/cpu/vulnerabilities"
	if entries, err := readDir(vulnDir); err == nil {
		observed = true
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			raw, readErr := readFile(filepath.Join(vulnDir, entry.Name()))
			if readErr != nil {
				continue
			}
			s.Vulnerabilities = append(s.Vulnerabilities, model.KernelVulnerability{Name: entry.Name(), Status: strings.TrimSpace(string(raw))})
		}
		sort.Slice(s.Vulnerabilities, func(i, j int) bool { return s.Vulnerabilities[i].Name < s.Vulnerabilities[j].Name })
	} else if !errors.Is(err, os.ErrNotExist) {
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "kernel vulnerabilities: " + err.Error()})
	}
	lookup, run := c.lookPath, c.run
	if lookup == nil {
		lookup = exec.LookPath
	}
	if run == nil {
		run = runCommand
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	isRoot := os.Geteuid() == 0
	var reduced []string
	if path, err := lookup("journalctl"); err == nil {
		s.JournalWindow = journalWindow
		// Authentication outcomes come from the authpriv facility; scanning an
		// unfiltered record tail found them only by luck.
		if raw, runErr := boundedCommand(ctx, timeout, run, path, "--since=-"+journalWindow, "--no-pager", "--output=cat", "--lines="+journalMaxRecords, authprivFacility); runErr == nil {
			observed = true
			auth, _, _ := ParseJournalSecurity(string(raw))
			s.FailedAuthAttempts = uintPtr(auth)
			if !isRoot {
				reduced = append(reduced, "authentication journal records are restricted to privileged users")
			}
		} else if ctx.Err() != nil {
			return collect.Data{}, ctx.Err()
		} else {
			diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "authentication journal: " + runErr.Error()})
		}
		// SELinux AVC and AppArmor denials are emitted by the kernel.
		if raw, runErr := boundedCommand(ctx, timeout, run, path, "--since=-"+journalWindow, "-k", "--no-pager", "--output=cat", "--lines="+journalMaxRecords); runErr == nil {
			observed = true
			_, selinux, apparmor := ParseJournalSecurity(string(raw))
			s.SELinuxDenials, s.AppArmorDenials = uintPtr(selinux), uintPtr(apparmor)
		} else if ctx.Err() != nil {
			return collect.Data{}, ctx.Err()
		} else {
			diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "kernel denial journal: " + runErr.Error()})
		}
	} else {
		reduced = append(reduced, "journalctl is unavailable; authentication and denial counts were not collected")
	}
	if path, err := lookup("who"); err == nil {
		if raw, runErr := boundedCommand(ctx, timeout, run, path); runErr == nil {
			observed = true
			n := uint64(ParseSessions(string(raw)))
			s.ActiveSessions = &n
		} else if ctx.Err() != nil {
			return collect.Data{}, ctx.Err()
		} else {
			diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "active sessions: " + runErr.Error()})
		}
	}
	if path, err := lookup("coredumpctl"); err == nil {
		if raw, runErr := boundedCommand(ctx, timeout, run, path, "list", "--since=-24h", "--no-pager", "--no-legend"); runErr == nil {
			observed = true
			n := uint64(ParseCoreDumps(string(raw)))
			s.CoreDumps = &n
		} else if ctx.Err() != nil {
			return collect.Data{}, ctx.Err()
		}
		// coredumpctl exits non-zero when it has nothing to report, so a
		// failure here is not distinguishable from an empty result and is
		// deliberately not raised as missing coverage.
	}
	if entries, err := readDir("/var/crash"); err == nil {
		observed = true
		for i, entry := range entries {
			if i >= 200 {
				break
			}
			if !entry.IsDir() && entry.Name() != "" {
				s.CrashArtifacts = append(s.CrashArtifacts, entry.Name())
			}
		}
		sort.Strings(s.CrashArtifacts)
	}
	s.Available = observed
	privileges := &model.Privileges{IsRoot: isRoot, ReducedCoverage: reduced}
	return collect.Data{Security: s, Privileges: privileges, Diagnostics: diagnostics}, nil
}

func boundedCommand(parent context.Context, timeout time.Duration, run func(context.Context, string, ...string) ([]byte, error), path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return run(ctx, path, args...)
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Output is truncated rather than abandoned; a partial journal read still
	// yields countable records.
	result, err := command.Run(ctx, command.Options{MaxOutput: maxCommandOutput}, name, args...)
	return result.Output, err
}

func uintPtr(v uint64) *uint64 { return &v }

// ParseJournalSecurity classifies high-signal auth and MAC denial messages.
func ParseJournalSecurity(output string) (failedAuth, selinuxDenials, apparmorDenials uint64) {
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "failed password") || strings.Contains(lower, "authentication failure") || strings.Contains(lower, "invalid user") {
			failedAuth++
		}
		if strings.Contains(lower, "avc:") && strings.Contains(lower, "denied") {
			selinuxDenials++
		}
		if strings.Contains(lower, "apparmor") && strings.Contains(lower, "denied") {
			apparmorDenials++
		}
	}
	return
}

func ParseSessions(output string) int {
	n := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

func ParseCoreDumps(output string) int {
	n := 0
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.Contains(strings.ToLower(trimmed), "no coredumps found") {
			n++
		}
	}
	return n
}

func taintedModuleNames(readFile func(string) ([]byte, error), output string) []string {
	var modules []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		// The name becomes a path component. The kernel does not permit
		// separators in module names, so validating it costs nothing and
		// removes the question of what a malformed source could reach.
		if !validModuleName(name) {
			continue
		}
		taint, err := readFile("/sys/module/" + name + "/taint")
		if err == nil && strings.TrimSpace(string(taint)) != "" {
			modules = append(modules, name)
		}
	}
	return modules
}

func validModuleName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}
