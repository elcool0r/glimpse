package kernel

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/model"
)

func TestParseEventsUsesExplicitPatterns(t *testing.T) {
	input := `kernel: generic error is not actionable
kernel: Out of memory: Killed process 99 (worker)
kernel: INFO: task backup:12 blocked for more than 120 seconds.
kernel: blk_update_request: I/O error, dev sda, sector 42
kernel: EXT4-fs error (device sda1): ext4_find_entry:1463
kernel: Hardware Error: CPU 0: Machine Check Event`
	got := ParseEvents(input, time.Now())
	kinds := make([]string, len(got))
	for i, event := range got {
		kinds[i] = event.Kind
	}
	want := []string{"oom", "blocked_task", "io_error", "filesystem_error", "hardware_error"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("got %#v, want %#v", kinds, want)
	}
}

func TestParseEventsRecognizesHighSignalKernelEventsOnce(t *testing.T) {
	input := `kernel: Memory cgroup out of memory: Killed process 12
kernel: Killed process 12 (worker)
kernel: Kernel panic - not syncing: Fatal exception
kernel: BUG: unable to handle kernel NULL pointer dereference
kernel: nvme0: I/O 12 QID 1 timeout, reset controller
kernel: ZFS: pool tank degraded due to an error
kernel: CPU0: Thermal throttling asserted`
	got := ParseEvents(input, time.Now())
	kinds := make([]string, len(got))
	for i, event := range got {
		kinds[i] = event.Kind
	}
	want := []string{"cgroup_oom", "kernel_panic", "kernel_oops", "nvme_error", "zfs_error", "thermal_throttling"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("got %#v, want %#v", kinds, want)
	}
}

func TestParseEventsRecognizesNewPatterns(t *testing.T) {
	input := `kernel: igb 0000:01:00.0 enp7s0: NIC Link is Down
kernel: igb 0000:01:00.0 enp7s0: NIC Link is Up 1000 Mbps Full Duplex
kernel: python3[12345]: segfault at 0 ip 00007f1234567890 sp 00007ffe12345678 error 4
kernel: NETDEV WATCHDOG: eth0 (r8169): transmit queue 0 timed out
kernel: EXT4-fs (sda1): re-mounting filesystem read-only
systemd[1]: Failed to write to /var/lib/foo: No space left on device`
	got := ParseEvents(input, time.Now())
	kinds := make([]string, len(got))
	for i, event := range got {
		kinds[i] = event.Kind
	}
	want := []string{"link_down", "link_up", "segfault", "netdev_watchdog", "filesystem_readonly_remount", "disk_full"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("got %#v, want %#v", kinds, want)
	}
}

// A virtual interface like a docker veth or a VM's tap device never actually
// emits the "NIC Link is Up/Down" driver message -- that phrasing comes
// specifically from physical Ethernet/Wi-Fi drivers -- but the filter is a
// deliberate backstop in case one ever does.
func TestFilterVirtualLinkEventsDropsSoftwareInterfaces(t *testing.T) {
	events := []model.LogEvent{
		{Kind: "link_down", Message: "enp7s0: NIC Link is Down"},
		{Kind: "link_down", Message: "veth3f2a91: NIC Link is Down"},
		{Kind: "link_up", Message: "docker0: NIC Link is Up"},
		{Kind: "oom", Message: "unrelated event, must pass through"},
	}
	got := filterVirtualLinkEvents(events)
	if len(got) != 2 {
		t.Fatalf("expected the two virtual-interface link events dropped, got %#v", got)
	}
	if got[0].Message != "enp7s0: NIC Link is Down" || got[1].Kind != "oom" {
		t.Fatalf("unexpected surviving events: %#v", got)
	}
}

// The prefix match must anchor to a word boundary, not any substring --
// otherwise a real interface whose name happens to contain "tap" or "wg" as
// a coincidental substring would be wrongly excluded.
func TestIsVirtualInterfaceMessageRequiresWordBoundary(t *testing.T) {
	if isVirtualInterfaceMessage("enp7s0: NIC Link is Down") {
		t.Fatal("a real interface name must not match")
	}
	if !isVirtualInterfaceMessage("veth1234: NIC Link is Down") {
		t.Fatal("a veth interface must match")
	}
	if !isVirtualInterfaceMessage("docker0: NIC Link is Up") {
		t.Fatal("docker0 must match")
	}
}

// The same incident kind spotted by two different scans (a plausible overlap
// once ENOSPC-style journal-wide grepping was added alongside the -k scans)
// must not be reported twice.
func TestAppendNewEventsDeduplicatesAcrossScans(t *testing.T) {
	events := appendNewEvents(nil, []model.LogEvent{{Kind: "disk_full", Message: "first"}})
	events = appendNewEvents(events, []model.LogEvent{{Kind: "disk_full", Message: "second"}, {Kind: "segfault", Message: "third"}})
	if len(events) != 2 {
		t.Fatalf("expected the duplicate disk_full dropped, got %#v", events)
	}
	if events[0].Message != "first" || events[1].Kind != "segfault" {
		t.Fatalf("unexpected merge result: %#v", events)
	}
}

func TestParseEventsKeepsNewestCanonicalEvent(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	old := now.Add(-2 * time.Hour).Unix()
	recent := now.Add(-time.Minute).Unix()
	got := ParseEvents(
		itoa(old)+" host kernel: Out of memory: old\n"+
			itoa(recent)+" host kernel: Killed process 42 (worker)", now)
	if len(got) != 1 {
		t.Fatalf("got %d events, want one canonical OOM event: %#v", len(got), got)
	}
	if got[0].Message != "Killed process 42 (worker)" || got[0].AgeSeconds == nil || *got[0].AgeSeconds > 61 {
		t.Fatalf("old OOM survived instead of recent event: %#v", got[0])
	}

	// The reverse order must keep the already encountered recent event.
	reversed := ParseEvents(
		itoa(recent)+" host kernel: Killed process 42 (worker)\n"+
			itoa(old)+" host kernel: Out of memory: old", now)
	if len(reversed) != 1 || reversed[0].Message != "Killed process 42 (worker)" {
		t.Fatalf("reverse-order scan regressed to old event: %#v", reversed)
	}
}

func TestAppendNewEventsKeepsNewestAcrossScansAndCanonicalOOM(t *testing.T) {
	events := appendNewEvents(nil, []model.LogEvent{{Kind: "oom", Message: "old", AgeSeconds: seconds(2 * time.Hour)}})
	events = appendNewEvents(events, []model.LogEvent{{Kind: "cgroup_oom", Message: "recent", AgeSeconds: seconds(time.Minute)}})
	if len(events) != 1 || events[0].Kind != "cgroup_oom" || events[0].Message != "recent" {
		t.Fatalf("cross-scan canonical OOM did not retain newest event: %#v", events)
	}

	// Ordinary I/O events use the same newest-event rule, even when a later
	// scan returns records in reverse chronological order.
	events = appendNewEvents(events, []model.LogEvent{
		{Kind: "io_error", Message: "older", AgeSeconds: seconds(2 * time.Hour)},
		{Kind: "io_error", Message: "newest", AgeSeconds: seconds(time.Minute)},
	})
	if len(events) != 2 || events[1].Message != "newest" {
		t.Fatalf("cross-scan I/O event selection regressed: %#v", events)
	}
}

func TestEventAgeSelectionPrefersKnownAndStableTies(t *testing.T) {
	known := seconds(time.Minute)
	events := appendNewEvents(nil, []model.LogEvent{{Kind: "io_error", Message: "unknown"}})
	events = appendNewEvents(events, []model.LogEvent{{Kind: "io_error", Message: "known", AgeSeconds: known}})
	if events[0].Message != "known" {
		t.Fatalf("known timestamp should replace unknown evidence: %#v", events)
	}
	events = appendNewEvents(events, []model.LogEvent{{Kind: "io_error", Message: "unknown later"}})
	if events[0].Message != "known" {
		t.Fatalf("unknown timestamp should not replace known evidence: %#v", events)
	}
	events = appendNewEvents(events, []model.LogEvent{{Kind: "io_error", Message: "equal age", AgeSeconds: known}})
	if events[0].Message != "known" {
		t.Fatalf("equal ages should retain first encounter: %#v", events)
	}
}

func TestParseEventsLeavesMalformedTimestampAgeUnknown(t *testing.T) {
	for _, timestamp := range []string{"NaN", "+Inf", "-1"} {
		t.Run(timestamp, func(t *testing.T) {
			events := ParseEvents(timestamp+" host kernel: Out of memory: malformed", time.Unix(2_000_000_000, 0))
			if len(events) != 1 || events[0].AgeSeconds != nil {
				t.Fatalf("malformed timestamp must remain unknown, got %#v", events)
			}
		})
	}
}

func TestNewestOOMRemainsCriticalInAnalysis(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	old := now.Add(-2 * time.Hour).Unix()
	recent := now.Add(-time.Minute).Unix()
	events := ParseEvents(itoa(old)+" host kernel: Out of memory: old\n"+itoa(recent)+" host kernel: Killed process 42", now)
	report := &model.Report{Metrics: model.Metrics{Kernel: &model.Kernel{Available: true, Events: events}}}
	analyze.Report(report)
	for _, finding := range report.Findings {
		if finding.ID == "kernel-oom" {
			if finding.Severity != model.SeverityCritical {
				t.Fatalf("newest OOM should remain critical, got %#v", finding)
			}
			return
		}
	}
	t.Fatalf("kernel OOM finding missing: %#v", report.Findings)
}

func seconds(duration time.Duration) *float64 {
	value := duration.Seconds()
	return &value
}

func itoa(value int64) string {
	return strconv.FormatInt(value, 10)
}

func TestUnavailableJournalIsNotAnError(t *testing.T) {
	c := New()
	c.lookPath = func(string) (string, error) { return "", errors.New("missing") }
	data, err := c.Collect(context.Background())
	if err != nil || data.Kernel == nil || data.Kernel.Available {
		t.Fatalf("data=%#v err=%v", data, err)
	}
}

func TestCollectorUsesPortableKernelShortOption(t *testing.T) {
	var calls [][]string
	c := New()
	c.lookPath = func(string) (string, error) { return "journalctl", nil }
	c.run = func(_ context.Context, _ string, got ...string) ([]byte, error) {
		calls = append(calls, got)
		return nil, nil
	}
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatalf("expected 3 journalctl invocations (priority scan, kernel grep scan, enospc grep scan), got %d: %#v", len(calls), calls)
	}
	for _, args := range calls {
		for _, arg := range args {
			if arg == "--kernel" {
				t.Fatalf("unsupported option used: %q", args)
			}
		}
	}
	// The first two scans read the kernel ring buffer; the third (ENOSPC)
	// deliberately does not, since applications log that, not the kernel.
	for i, args := range calls[:2] {
		found := false
		for _, arg := range args {
			found = found || arg == "-k"
		}
		if !found {
			t.Fatalf("call %d: kernel option missing: %q", i, args)
		}
	}
	for _, arg := range calls[2] {
		if arg == "-k" {
			t.Fatalf("the ENOSPC scan must not be kernel-ring-buffer-only: %q", calls[2])
		}
	}
}

func TestNoJournalMatchesIsNotUnavailableCoverage(t *testing.T) {
	noMatch := exec.Command("sh", "-c", "exit 1").Run()
	if !noJournalMatches(noMatch) {
		t.Fatalf("exit status 1 = %v, want no journal matches", noMatch)
	}
	c := New()
	c.lookPath = func(string) (string, error) { return "journalctl", nil }
	calls := 0
	c.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, nil
		}
		return nil, noMatch
	}
	data, err := c.Collect(context.Background())
	if err != nil || data.Kernel == nil || !data.Kernel.Available || len(data.Diagnostics) != 0 {
		t.Fatalf("empty targeted scans must remain healthy coverage: data=%+v err=%v", data, err)
	}
}

func TestTargetedJournalTimeoutExplainsCoverageAndManualFollowUp(t *testing.T) {
	c := New()
	c.Timeout = time.Millisecond
	c.lookPath = func(string) (string, error) { return "journalctl", nil }
	calls := 0
	c.run = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, nil
		}
		<-ctx.Done()
		return nil, errors.New("signal: killed")
	}
	data, err := c.Collect(context.Background())
	if err != nil || len(data.Diagnostics) != 2 {
		t.Fatalf("timed-out targeted scans must be nonfatal coverage diagnostics: data=%+v err=%v", data, err)
	}
	for _, diagnostic := range data.Diagnostics {
		if strings.Contains(diagnostic.Detail, "Disk-full journal coverage") && diagnostic.Status != "info" {
			t.Fatalf("timed-out journal coverage should be informational: %+v", diagnostic)
		}
		if !strings.Contains(diagnostic.Detail, "does not change the kernel health result") || !strings.Contains(diagnostic.Detail, "exceeded its 1ms budget") || !strings.Contains(diagnostic.Detail, "To investigate manually, run: journalctl") {
			t.Fatalf("diagnostic did not explain timeout and follow-up: %+v", diagnostic)
		}
	}
}

func TestDefaultTargetedJournalQueriesGetLongerBudget(t *testing.T) {
	c := New()
	c.lookPath = func(string) (string, error) { return "journalctl", nil }
	var deadlines []time.Duration
	c.run = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("journal query has no timeout")
		}
		deadlines = append(deadlines, time.Until(deadline))
		return nil, nil
	}
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(deadlines) != 3 || deadlines[0] > commandTimeout || deadlines[1] <= commandTimeout || deadlines[2] <= commandTimeout {
		t.Fatalf("query budgets = %v, want 4s primary then longer targeted budgets", deadlines)
	}
}
