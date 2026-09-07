package render

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/model"
)

func ageSeconds(d time.Duration) *float64 {
	v := d.Seconds()
	return &v
}

func TestTimelineHiddenByDefaultWithoutACritical(t *testing.T) {
	report := model.Report{
		Host:    model.Host{Hostname: "host"},
		Score:   model.Score{Status: model.SeverityWarning},
		Metrics: model.Metrics{Kernel: &model.Kernel{Available: true, Events: []model.LogEvent{{Kind: "oom", Message: "Out of memory", AgeSeconds: ageSeconds(time.Minute)}}}},
	}
	var out strings.Builder
	Write(&out, report, Options{})
	if strings.Contains(out.String(), "Recent events") {
		t.Fatalf("timeline should not show without a critical finding or --events:\n%s", out.String())
	}
}

func TestTimelineShownWhenCritical(t *testing.T) {
	report := model.Report{
		Host:    model.Host{Hostname: "host"},
		Score:   model.Score{Status: model.SeverityCritical},
		Metrics: model.Metrics{Kernel: &model.Kernel{Available: true, Events: []model.LogEvent{{Kind: "oom", Message: "Out of memory: Killed process 99 (postgres)", AgeSeconds: ageSeconds(time.Minute)}}}},
	}
	var out strings.Builder
	Write(&out, report, Options{})
	if !strings.Contains(out.String(), "Recent events") || !strings.Contains(out.String(), "Killed process 99 (postgres)") {
		t.Fatalf("expected the timeline for a critical report:\n%s", out.String())
	}
}

func TestTimelineShownWithEventsFlagOnHealthyReport(t *testing.T) {
	report := model.Report{
		Host:    model.Host{Hostname: "host"},
		Score:   model.Score{Status: model.SeverityOK},
		Metrics: model.Metrics{Kernel: &model.Kernel{Available: true, Events: []model.LogEvent{{Kind: "oom", Message: "Out of memory", AgeSeconds: ageSeconds(time.Minute)}}}},
	}
	var out strings.Builder
	Write(&out, report, Options{Events: true})
	if !strings.Contains(out.String(), "Recent events") {
		t.Fatalf("--events should force the timeline even on a healthy report:\n%s", out.String())
	}
}

// localNoonToday returns a time at local noon today, far from any midnight
// boundary regardless of the machine's timezone -- the tests that offset
// from it by a few hours stay deterministic wherever they run, unlike a
// fixed UTC instant would once converted to local time for display.
func localNoonToday(t *testing.T) time.Time {
	t.Helper()
	now := time.Now().Local()
	return time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, now.Location())
}

// A silently empty section is indistinguishable from --events doing
// nothing; the report must say plainly that nothing qualified.
func TestTimelineExplainsWhenNoEventsQualify(t *testing.T) {
	report := model.Report{
		Host:    model.Host{Hostname: "host"},
		Score:   model.Score{Status: model.SeverityOK},
		Metrics: model.Metrics{CPU: &model.CPU{}},
		Findings: []model.Finding{
			{ID: "zombies", Severity: model.SeverityInfo, Category: "process", Title: "Zombie processes present"},
			{ID: "security-reboot-required", Severity: model.SeverityInfo, Category: "security", Title: "Reboot is pending"},
		},
	}
	var out strings.Builder
	Write(&out, report, Options{Events: true})
	if !strings.Contains(out.String(), "Recent events (today)") {
		t.Fatalf("expected the timeline header even with no qualifying events:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "No kernel, container, service, package, login, or sudo events") {
		t.Fatalf("expected an explicit empty-state message:\n%s", out.String())
	}
}

// The rendered timeline reads top-to-bottom like a log or scrollback: oldest
// first, latest last, closest to whatever comes after it in the report.
func TestRenderedTimelineOrdersOldestFirst(t *testing.T) {
	now := localNoonToday(t)
	report := model.Report{
		Host:        model.Host{Hostname: "host"},
		GeneratedAt: now,
		Score:       model.Score{Status: model.SeverityCritical},
		Metrics: model.Metrics{Kernel: &model.Kernel{Available: true, Events: []model.LogEvent{
			{Kind: "oom", Message: "older event", AgeSeconds: ageSeconds(2 * time.Hour)},
			{Kind: "panic", Message: "newer event", AgeSeconds: ageSeconds(10 * time.Minute)},
		}}},
	}
	var out strings.Builder
	Write(&out, report, Options{ASCII: true})
	text := out.String()
	olderIdx := strings.Index(text, "older event")
	newerIdx := strings.Index(text, "newer event")
	if olderIdx == -1 || newerIdx == -1 || olderIdx > newerIdx {
		t.Fatalf("expected the older event to render before the newer one:\n%s", text)
	}
}

// The events being cut by the cap are the oldest ones, so the surviving
// list must still end with the single most recent event, not have it
// pushed out by the cap.
func TestTimelineCapKeepsTheMostRecentEvents(t *testing.T) {
	now := localNoonToday(t)
	var kernelEvents []model.LogEvent
	for i := 0; i < maxTimelineEvents; i++ {
		kernelEvents = append(kernelEvents, model.LogEvent{Kind: "oom", Message: fmt.Sprintf("event-%d", i), AgeSeconds: ageSeconds(time.Duration(maxTimelineEvents-i) * time.Minute)})
	}
	kernelEvents = append(kernelEvents, model.LogEvent{Kind: "panic", Message: "most-recent", AgeSeconds: ageSeconds(time.Second)})
	report := model.Report{
		Host:        model.Host{Hostname: "host"},
		GeneratedAt: now,
		Score:       model.Score{Status: model.SeverityCritical},
		Metrics:     model.Metrics{Kernel: &model.Kernel{Available: true, Events: kernelEvents}},
	}
	var out strings.Builder
	Write(&out, report, Options{ASCII: true})
	if !strings.Contains(out.String(), "most-recent") {
		t.Fatalf("expected the most recent event to survive the cap:\n%s", out.String())
	}
	if strings.Contains(out.String(), "event-0") {
		t.Fatalf("expected the single oldest event dropped by the cap:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "event-1") {
		t.Fatalf("expected the event right at the cap boundary to survive:\n%s", out.String())
	}
}

// An event from before local midnight is outside the "today" window and
// must not appear, even though it is still within, say, the kernel scan's
// own 24h collection window.
func TestTimelineExcludesEventsBeforeToday(t *testing.T) {
	todayNoon := localNoonToday(t)
	now := todayNoon.Add(-11 * time.Hour) // 1am local today
	report := model.Report{
		GeneratedAt: now,
		Metrics: model.Metrics{Kernel: &model.Kernel{Available: true, Events: []model.LogEvent{
			{Kind: "oom", Message: "yesterday", AgeSeconds: ageSeconds(3 * time.Hour)},
			{Kind: "oom", Message: "today", AgeSeconds: ageSeconds(30 * time.Minute)},
		}}},
	}
	events := collectTimelineEvents(report)
	if len(events) != 1 || events[0].label != "today" {
		t.Fatalf("expected only today's event, got %#v", events)
	}
}

// A kernel/container event without an age cannot be placed on a timeline
// and must be left out rather than guessed at.
func TestTimelineSkipsEventsWithoutAnAge(t *testing.T) {
	report := model.Report{
		GeneratedAt: time.Now(),
		Metrics:     model.Metrics{Kernel: &model.Kernel{Available: true, Events: []model.LogEvent{{Kind: "oom", Message: "unknown time"}}}},
	}
	if events := collectTimelineEvents(report); len(events) != 0 {
		t.Fatalf("expected no events without an age, got %#v", events)
	}
}

// Generic "error"/"failure" log wording is noise even in the timeline; only
// the same concrete failure signatures the analyzer treats as actionable
// belong here.
func TestTimelineExcludesGenericContainerLogNoise(t *testing.T) {
	report := model.Report{
		GeneratedAt: time.Now(),
		Metrics: model.Metrics{Containers: []model.ContainerRuntime{{Runtime: "docker", Containers: []model.Container{
			{Name: "web", LogEvents: []model.LogEvent{
				{Kind: "error", Message: "generic error line", AgeSeconds: ageSeconds(time.Minute)},
				{Kind: "oom", Message: "OOM killed in container", AgeSeconds: ageSeconds(time.Minute)},
			}},
		}}}},
	}
	events := collectTimelineEvents(report)
	if len(events) != 1 || !strings.Contains(events[0].label, "OOM killed in container") {
		t.Fatalf("expected only the specific log kind to appear, got %#v", events)
	}
}

func TestTimelineIncludesRebootFromHostBootTime(t *testing.T) {
	now := localNoonToday(t)
	bootTime := now.Add(-3 * time.Hour)
	report := model.Report{
		GeneratedAt: now,
		Host:        model.Host{BootTime: &bootTime},
	}
	events := collectTimelineEvents(report)
	if len(events) != 1 || events[0].source != "system" || events[0].label != "system booted" {
		t.Fatalf("expected a system-booted event, got %#v", events)
	}
	if !events[0].at.Equal(bootTime) {
		t.Fatalf("expected the real boot time, got %v", events[0].at)
	}
}

// A boot from before today is outside the timeline's window and must not
// appear, the same as any other event.
func TestTimelineExcludesRebootFromBeforeToday(t *testing.T) {
	now := localNoonToday(t)
	bootTime := now.Add(-30 * 24 * time.Hour)
	report := model.Report{
		GeneratedAt: now,
		Host:        model.Host{BootTime: &bootTime},
	}
	if events := collectTimelineEvents(report); len(events) != 0 {
		t.Fatalf("expected no events for an old boot time, got %#v", events)
	}
}

func TestTimelineIncludesLiveContainerAndSystemdFacts(t *testing.T) {
	report := model.Report{
		GeneratedAt: time.Now(),
		Metrics: model.Metrics{
			Containers: []model.ContainerRuntime{{Runtime: "docker", Containers: []model.Container{{Name: "web", OOMKilled: true}}}},
			Systemd:    &model.Systemd{Available: true, FailedUnits: []string{"nginx.service"}, RestartingUnits: []model.SystemdUnitRestart{{Unit: "crashloop.service", RestartsDelta: 4}}},
		},
	}
	events := collectTimelineEvents(report)
	var labels []string
	for _, e := range events {
		labels = append(labels, e.label)
	}
	joined := strings.Join(labels, " | ")
	for _, want := range []string{"container web was OOM-killed", "nginx.service failed", "crashloop.service restarted 4 time(s)"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %v", want, labels)
		}
	}
}

// The real-world bug report: a service restarted a few minutes before
// glimpse ran has no RestartsDelta during this specific sample, but its
// ActiveEnterTimestamp still places it on the timeline with a real time.
func TestTimelineUsesRecentStartsForServicesRestartedBeforeTheSample(t *testing.T) {
	now := localNoonToday(t)
	report := model.Report{
		GeneratedAt: now,
		Metrics: model.Metrics{
			Systemd: &model.Systemd{Available: true, RecentStarts: []model.SystemdUnitStart{
				{Unit: "systemd-resolved.service", At: now.Add(-5 * time.Minute)},
			}},
		},
	}
	events := collectTimelineEvents(report)
	if len(events) != 1 || !strings.Contains(events[0].label, "systemd-resolved.service (re)started") {
		t.Fatalf("expected the precisely-timed restart, got %#v", events)
	}
	if !events[0].at.Equal(now.Add(-5 * time.Minute)) {
		t.Fatalf("expected the real restart time, got %v", events[0].at)
	}
}

// When both a precise timestamp and a live restart count are known for the
// same unit, the count is folded into the precisely-timed entry instead of
// producing two separate, redundant lines.
func TestTimelineMergesRecentStartWithLiveRestartCount(t *testing.T) {
	now := localNoonToday(t)
	report := model.Report{
		GeneratedAt: now,
		Metrics: model.Metrics{
			Systemd: &model.Systemd{
				Available:       true,
				RecentStarts:    []model.SystemdUnitStart{{Unit: "crashloop.service", At: now.Add(-time.Minute)}},
				RestartingUnits: []model.SystemdUnitRestart{{Unit: "crashloop.service", RestartsDelta: 4}},
			},
		},
	}
	events := collectTimelineEvents(report)
	if len(events) != 1 {
		t.Fatalf("expected exactly one merged entry, got %#v", events)
	}
	if !strings.Contains(events[0].label, "crashloop.service") || !strings.Contains(events[0].label, "4 time(s)") {
		t.Fatalf("expected the merged entry to name both the unit and the count: %q", events[0].label)
	}
	if !events[0].at.Equal(now.Add(-time.Minute)) {
		t.Fatalf("expected the merged entry to use the precise time, not \"now\": %v", events[0].at)
	}
}

func TestTimelineIncludesPackageActivityWithSource(t *testing.T) {
	now := localNoonToday(t)
	report := model.Report{
		GeneratedAt: now,
		Metrics: model.Metrics{PackageActivity: []model.PackageActivity{
			{At: now.Add(-2 * time.Hour), Manager: "apt", Summary: "3 packages upgraded"},
		}},
	}
	events := collectTimelineEvents(report)
	if len(events) != 1 || events[0].source != "apt" || events[0].label != "3 packages upgraded" {
		t.Fatalf("unexpected events: %#v", events)
	}
}

func TestTimelineIncludesLoginsWithDetail(t *testing.T) {
	now := localNoonToday(t)
	report := model.Report{
		GeneratedAt: now,
		Metrics: model.Metrics{Logins: []model.LoginEvent{
			{At: now.Add(-time.Hour), User: "daniel", Source: "203.0.113.5", Method: "publickey"},
		}},
	}
	events := collectTimelineEvents(report)
	if len(events) != 1 || events[0].source != "ssh" {
		t.Fatalf("expected an ssh-sourced login event: %#v", events)
	}
	if !strings.Contains(events[0].label, "daniel") || !strings.Contains(events[0].label, "203.0.113.5") || !strings.Contains(events[0].label, "publickey") {
		t.Fatalf("login label missing detail: %q", events[0].label)
	}
}

func TestTimelineIncludesSudoCommandsWithSource(t *testing.T) {
	now := localNoonToday(t)
	report := model.Report{
		GeneratedAt: now,
		Metrics: model.Metrics{SudoCommands: []model.SudoEvent{
			{At: now.Add(-time.Hour), User: "daniel", RunAs: "root", Command: "/usr/bin/apt update"},
		}},
	}
	events := collectTimelineEvents(report)
	if len(events) != 1 || events[0].source != "sudo" {
		t.Fatalf("expected a sudo-sourced event: %#v", events)
	}
	if !strings.Contains(events[0].label, "daniel") || !strings.Contains(events[0].label, "apt update") {
		t.Fatalf("sudo label missing detail: %q", events[0].label)
	}
}

// A long command must not be dropped entirely, just capped for readability.
func TestTimelineTruncatesLongSudoCommands(t *testing.T) {
	now := localNoonToday(t)
	longCmd := strings.Repeat("x", 200)
	report := model.Report{
		GeneratedAt: now,
		Metrics: model.Metrics{SudoCommands: []model.SudoEvent{
			{At: now.Add(-time.Hour), User: "daniel", RunAs: "root", Command: longCmd},
		}},
	}
	events := collectTimelineEvents(report)
	if len(events) != 1 || len(events[0].label) >= len(longCmd) {
		t.Fatalf("expected the command truncated, got label of length %d", len(events[0].label))
	}
}

// The source tag lets a reader know which log to open next without guessing.
func TestRenderedTimelineShowsSourceTag(t *testing.T) {
	now := localNoonToday(t)
	report := model.Report{
		Host:        model.Host{Hostname: "host"},
		GeneratedAt: now,
		Score:       model.Score{Status: model.SeverityCritical},
		Metrics: model.Metrics{Kernel: &model.Kernel{Available: true, Events: []model.LogEvent{
			{Kind: "oom", Message: "Out of memory", AgeSeconds: ageSeconds(time.Minute)},
		}}},
	}
	var out strings.Builder
	Write(&out, report, Options{ASCII: true})
	if !strings.Contains(out.String(), "[kernel]") {
		t.Fatalf("expected a [kernel] source tag:\n%s", out.String())
	}
}

func TestTimelineCapsEventCountWithOmittedNote(t *testing.T) {
	now := time.Now()
	var kernelEvents []model.LogEvent
	for i := 0; i < maxTimelineEvents+5; i++ {
		kernelEvents = append(kernelEvents, model.LogEvent{Kind: "oom", Message: "event", AgeSeconds: ageSeconds(time.Duration(i+1) * time.Minute)})
	}
	report := model.Report{
		GeneratedAt: now,
		Score:       model.Score{Status: model.SeverityCritical},
		Metrics:     model.Metrics{Kernel: &model.Kernel{Available: true, Events: kernelEvents}},
	}
	var out strings.Builder
	Write(&out, report, Options{})
	if !strings.Contains(out.String(), "5 more event(s) earlier today") {
		t.Fatalf("expected an omitted-count note:\n%s", out.String())
	}
}
