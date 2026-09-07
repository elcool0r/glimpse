// Package kernel performs a deliberately bounded scan for a few high-signal
// kernel failure patterns, plus a small number of application-logged
// incidents (like ENOSPC) that share the same "one classified, timestamped
// event" shape. It never treats a generic "error" log line as a health
// event.
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
	// grepMaxLines bounds the two targeted --grep scans, which are already
	// narrowed server-side by journalctl and so need much less headroom
	// than the broad priority-based scan.
	grepMaxLines = 50
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
	run := c.run
	if run == nil {
		run = runCommand
	}
	now := time.Now()
	var diagnostics []model.CollectionStatus
	var events []model.LogEvent
	seen := make(map[string]struct{})

	// Primary scan: broad kernel-ring-buffer coverage at warning-and-above
	// priority. This is where oom/panic/oops/hardware/filesystem/nvme/io
	// errors are found; the priority filter is what keeps 200 lines from
	// being consumed by routine kernel chatter before reaching them.
	if output, runErr := runBounded(parent, run, timeout, path, "--boot=0", "--since=-24h", "-k", "--priority=warning", "--no-pager", "--output=short-unix", "--lines="+strconv.Itoa(maxLines)); runErr != nil {
		if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		}
		return collect.Data{Kernel: &model.Kernel{Available: false}, Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: runErr.Error()}}}, nil
	} else {
		events = appendNewEvents(events, seen, ParseEvents(string(output), now))
	}

	// Secondary scan: kernel-ring-buffer lines below warning priority that
	// are still worth surfacing (a segfault, or a NIC's own link-state
	// message). journalctl's own --grep narrows this server-side, so it
	// stays bounded without needing to widen the priority filter above and
	// risk routine info-level chatter crowding out the real signal.
	if output, runErr := runBounded(parent, run, timeout, path, "--boot=0", "--since=-24h", "-k", "--grep=segfault at|NIC Link is (Up|Down)", "--no-pager", "--output=short-unix", "--lines="+strconv.Itoa(grepMaxLines)); runErr != nil {
		if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		}
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "grep(kernel): " + runErr.Error()})
	} else {
		events = appendNewEvents(events, seen, filterVirtualLinkEvents(ParseEvents(string(output), now)))
	}

	// Tertiary scan: ENOSPC is reported by the application that hit it, not
	// the kernel, so this is the one scan here that is not -k restricted.
	if output, runErr := runBounded(parent, run, timeout, path, "--since=-24h", "--grep=No space left on device", "--no-pager", "--output=short-unix", "--lines="+strconv.Itoa(grepMaxLines)); runErr != nil {
		if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		}
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "grep(enospc): " + runErr.Error()})
	} else {
		events = appendNewEvents(events, seen, ParseEvents(string(output), now))
	}

	return collect.Data{Kernel: &model.Kernel{Available: true, Events: events}, Diagnostics: diagnostics}, nil
}

func runBounded(parent context.Context, run func(context.Context, string, ...string) ([]byte, error), timeout time.Duration, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return run(ctx, path, args...)
}

// appendNewEvents merges another scan's events, deduplicating by kind (the
// same key ParseEvents itself dedups within one scan) across the whole
// collection, so the same incident spotted by two different scans is not
// reported twice.
func appendNewEvents(events []model.LogEvent, seen map[string]struct{}, found []model.LogEvent) []model.LogEvent {
	for _, event := range found {
		key := event.Kind
		if key == "oom" || key == "cgroup_oom" {
			key = "oom"
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		events = append(events, event)
	}
	return events
}

// virtualInterfacePrefixes names software-created interfaces (container
// networking, VMs, VPNs, bridges) that filterVirtualLinkEvents excludes as a
// defensive backstop. In practice a virtual interface never emits the "NIC
// Link is Up/Down" message in the first place -- that phrasing comes from
// physical Ethernet/Wi-Fi drivers reporting real PHY state, which veth,
// bridge, tap and wireguard devices have no equivalent of -- so this rarely
// needs to reject anything; it exists for the driver that does something
// unexpected rather than as the primary filter.
var virtualInterfacePrefixes = []string{
	"veth", "docker", "br-", "virbr", "tap", "vnet", "cni", "flannel", "wg", "tun", "cali", "podman",
}

// filterVirtualLinkEvents drops link_up/link_down events whose message names
// a software-created interface. Every other kind passes through unchanged.
func filterVirtualLinkEvents(events []model.LogEvent) []model.LogEvent {
	kept := make([]model.LogEvent, 0, len(events))
	for _, event := range events {
		if (event.Kind == "link_up" || event.Kind == "link_down") && isVirtualInterfaceMessage(event.Message) {
			continue
		}
		kept = append(kept, event)
	}
	return kept
}

func isVirtualInterfaceMessage(message string) bool {
	lower := strings.ToLower(message)
	for _, prefix := range virtualInterfacePrefixes {
		if idx := strings.Index(lower, prefix); idx >= 0 {
			// Require the prefix to start a "word" (previous rune is not a
			// letter/digit) so it matches an interface name token rather
			// than an unrelated substring occurring in driver text.
			if idx == 0 || !isAlnum(lower[idx-1]) {
				return true
			}
		}
	}
	return false
}

func isAlnum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
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
	case strings.Contains(lower, "remounting filesystem read-only") || strings.Contains(lower, "re-mounting filesystem read-only") || strings.Contains(lower, "remounting filesystem read only"):
		return "filesystem_readonly_remount"
	case strings.Contains(lower, "xfs") && strings.Contains(lower, "corruption"):
		return "filesystem_corruption"
	case strings.Contains(lower, "ext4-fs error") || strings.Contains(lower, "btrfs error"):
		return "filesystem_error"
	case strings.Contains(lower, "machine check") || strings.Contains(lower, "hardware error"):
		return "hardware_error"
	case strings.Contains(lower, "netdev watchdog"):
		return "netdev_watchdog"
	case strings.Contains(lower, "zfs") && (strings.Contains(lower, "error") || strings.Contains(lower, "fault") || strings.Contains(lower, "degrad")):
		return "zfs_error"
	case strings.Contains(lower, "thermal") && (strings.Contains(lower, "throttl") || strings.Contains(lower, "critical")):
		return "thermal_throttling"
	case strings.Contains(lower, "segfault at"):
		return "segfault"
	case strings.Contains(lower, "nic link is down") || strings.Contains(lower, "link is down"):
		return "link_down"
	case strings.Contains(lower, "nic link is up") || strings.Contains(lower, "link is up"):
		return "link_up"
	case strings.Contains(lower, "no space left on device"):
		return "disk_full"
	default:
		return ""
	}
}
