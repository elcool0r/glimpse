// Package security collects small, read-only Linux security and maintenance facts.
package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/command"
	"github.com/elcool0r/glimpse/internal/model"
)

const (
	maxCommandOutput      = 256 << 10
	defaultCommandTimeout = 10 * time.Second
)

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
	// journalEventsWindow matches the timeline's own "today" scope, unlike the
	// 1h journalWindow above (which bounds the noisier failed-auth *count*
	// so its ratio has a well-defined denominator).
	journalEventsWindow = "24h"
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
		timeout = defaultCommandTimeout
	}
	isRoot := os.Geteuid() == 0
	var reduced []string
	var logins []model.LoginEvent
	var sudoCommands []model.SudoEvent
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
			diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: journalQueryDiagnostic("authentication journal", "failed-authentication counts for the last hour", timeout, runErr)})
		}
		// Interactive sudo commands: TTY=unknown (or an absent TTY field)
		// marks a cron job or script running with no controlling terminal,
		// which is excluded the same way a non-interactive SSH session is.
		if raw, runErr := boundedCommand(ctx, timeout, run, path, "_COMM=sudo", "--since=-"+journalEventsWindow, "--no-pager", "--output=short-unix", "--lines="+journalMaxRecords); runErr == nil {
			sudoCommands = ParseSudoCommands(string(raw))
		} else if ctx.Err() != nil {
			return collect.Data{}, ctx.Err()
		} else {
			diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: journalQueryDiagnostic("sudo journal", "interactive sudo-command events", timeout, runErr)})
		}
		// SELinux AVC and AppArmor denials are emitted by the kernel.
		if raw, runErr := boundedCommand(ctx, timeout, run, path, "--since=-"+journalWindow, "-k", "--no-pager", "--output=cat", "--lines="+journalMaxRecords); runErr == nil {
			observed = true
			_, selinux, apparmor := ParseJournalSecurity(string(raw))
			s.SELinuxDenials, s.AppArmorDenials = uintPtr(selinux), uintPtr(apparmor)
		} else if ctx.Err() != nil {
			return collect.Data{}, ctx.Err()
		} else {
			diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: journalQueryDiagnostic("kernel denial journal", "SELinux and AppArmor denial counts for the last hour", timeout, runErr)})
		}
	} else {
		reduced = append(reduced, "journalctl is unavailable; authentication and denial counts were not collected")
	}
	// Real interactive login sessions come from wtmp via `last`, not sshd's
	// own journal line: wtmp is only written for a session that allocates a
	// login shell, so a non-interactive `ssh host command` (no pty, no wtmp
	// record) is excluded by construction, which a text scan of sshd's
	// identical-looking "Accepted" line cannot do.
	if path, err := lookup("last"); err == nil {
		// last has no --no-legend option (unlike lsblk/findmnt and other
		// util-linux tools); passing it made the whole command fail with an
		// unrecognized-option error, silently producing zero logins. last's
		// own output never has a header line to suppress in the first place.
		if raw, runErr := boundedCommand(ctx, timeout, run, path, "--time-format=iso", "-i", "-n", "200"); runErr == nil {
			logins = ParseLastLogins(string(raw))
		} else if ctx.Err() != nil {
			return collect.Data{}, ctx.Err()
		} else {
			diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "last: " + runErr.Error()})
		}
	} else {
		reduced = append(reduced, "last is unavailable; login events were not collected")
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
	return collect.Data{Security: s, Privileges: privileges, Diagnostics: diagnostics, Logins: logins, SudoCommands: sudoCommands}, nil
}

func boundedCommand(parent context.Context, timeout time.Duration, run func(context.Context, string, ...string) ([]byte, error), path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	raw, err := run(ctx, path, args...)
	if ctx.Err() == context.DeadlineExceeded {
		return raw, fmt.Errorf("%w after %s", context.DeadlineExceeded, timeout)
	}
	return raw, err
}

func journalQueryDiagnostic(query, omitted string, timeout time.Duration, err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("%s query timed out after %s; %s were not collected", query, timeout, omitted)
	}
	return fmt.Sprintf("%s query failed; %s were not collected: %v", query, omitted, err)
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Output is truncated rather than abandoned; a partial journal read still
	// yields countable records.
	result, err := command.Run(ctx, command.Options{MaxOutput: maxCommandOutput}, name, args...)
	return result.Output, err
}

func uintPtr(v uint64) *uint64 { return &v }

var (
	// loginPseudoUsers are wtmp records that are not a real login: a boot
	// marker, a runlevel/shutdown record, or the "wtmp/btmp begins" trailer
	// line last prints at the end of its output.
	loginPseudoUsers = map[string]bool{"reboot": true, "shutdown": true, "runlevel": true, "wtmp": true, "btmp": true}
	// ipLikePattern matches an IPv4 address, or an IPv6 address containing
	// "::" compression -- the form last actually prints -- rather than any
	// bare run of colon-separated hex-looking groups, which would also
	// match an ordinary HH:MM:SS time (hex digits overlap decimal ones).
	// The IPv6 branch has no leading \b: an address last truncates to fit
	// its fixed-width host column can start directly with "::" (an
	// IPv4-mapped address like "::ffff:172.18.0."), and \b cannot anchor
	// between two non-word characters (a space and a colon), which would
	// otherwise make that case fail to match at all. "." is included so a
	// mapped address's embedded IPv4 tail is captured too.
	ipLikePattern  = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|[0-9a-fA-F.]*::[0-9a-fA-F.:]*`)
	isoTimePattern = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?`)
)

// ParseLastLogins extracts real interactive login sessions from `last
// --time-format=iso -i`. wtmp (last's own source) only gets a record when a
// session allocates a login shell/pty, so a non-interactive
// `ssh host command` invocation -- which allocates neither -- has no wtmp
// entry and is excluded by construction, unlike a raw scan of sshd's own
// log line (identical for both cases).
//
// Parsing is deliberately format-tolerant rather than column-exact: it
// looks for a leading username, an IP-shaped token anywhere in the line
// (present only for a remote/SSH session; a local console login has none
// and is correctly skipped), and the first ISO-8601 timestamp on the line
// (the session's start time; an end time or "still logged in" after it is
// not needed here). -i suppresses reverse-DNS hostname lookups, which
// would otherwise make this an unbounded-latency command on a host with
// broken DNS.
func ParseLastLogins(output string) []model.LoginEvent {
	var logins []model.LoginEvent
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		user := fields[0]
		if loginPseudoUsers[strings.ToLower(user)] {
			continue
		}
		loc := isoTimePattern.FindStringIndex(line)
		if loc == nil {
			continue
		}
		stamp := line[loc[0]:loc[1]]
		// The host/IP field always precedes the timestamp column in last's
		// output; searching only that prefix keeps the IP match from ever
		// colliding with digits inside the timestamp itself.
		source := ipLikePattern.FindString(line[:loc[0]])
		if source == "" {
			continue
		}
		at, err := parseFlexibleISO(stamp)
		if err != nil {
			continue
		}
		logins = append(logins, model.LoginEvent{At: at, User: user, Source: source})
	}
	sort.Slice(logins, func(i, j int) bool { return logins[i].At.Before(logins[j].At) })
	return logins
}

// parseFlexibleISO accepts both a colon-separated UTC offset ("+02:00", the
// documented ISO-8601 form) and the bare four-digit form ("+0200", what
// strftime's %z actually produces, which some `last` builds use verbatim
// for --time-format=iso).
func parseFlexibleISO(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02T15:04:05Z07:00", s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02T15:04:05Z0700", s)
}

// sudoCommandPattern matches sudo's own log line, e.g.
// "daniel : TTY=pts/1 ; PWD=/home/daniel ; USER=root ; COMMAND=/usr/bin/apt update".
// TTY is captured separately so a cron/script invocation (TTY=unknown, or no
// TTY field at all) can be excluded; COMMAND is captured greedily to the end
// of the line since an argument may itself contain " ; ".
var sudoCommandPattern = regexp.MustCompile(`^(\S+)\s*:.*?TTY=(\S+).*?USER=(\S+).*?COMMAND=(.*)$`)

// ParseSudoCommands reads a journalctl short-unix scan filtered to
// `_COMM=sudo`. Only commands run from a real terminal are kept: sudo
// itself logs TTY=unknown for a cron job or script, which has no
// controlling terminal, the same signal ParseLastLogins uses to exclude
// non-interactive SSH sessions.
func ParseSudoCommands(output string) []model.SudoEvent {
	var events []model.SudoEvent
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		stamp, rest, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		seconds, err := strconv.ParseFloat(stamp, 64)
		if err != nil || seconds <= 0 {
			continue
		}
		// rest: "<hostname> sudo[pid]: <message>"
		_, rest, ok = strings.Cut(rest, " ")
		if !ok {
			continue
		}
		_, message, ok := strings.Cut(rest, ": ")
		if !ok {
			continue
		}
		// sudo right-pads short usernames with leading spaces so its log
		// lines align in a fixed-width column ("    root :", "  daniel :");
		// the pattern below anchors to the start of the message and would
		// otherwise never match a padded username.
		m := sudoCommandPattern.FindStringSubmatch(strings.TrimSpace(message))
		if m == nil {
			continue
		}
		tty := m[2]
		if tty == "" || strings.EqualFold(tty, "unknown") {
			continue
		}
		events = append(events, model.SudoEvent{At: time.Unix(int64(seconds), 0), User: m[1], RunAs: m[3], Command: strings.TrimSpace(m[4])})
	}
	sort.Slice(events, func(i, j int) bool { return events[i].At.Before(events[j].At) })
	return events
}

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
