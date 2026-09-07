package render

import (
	"sort"
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
	if !strings.Contains(out.String(), "No kernel, container, or service events with a known time were recorded today.") {
		t.Fatalf("expected an explicit empty-state message:\n%s", out.String())
	}
}

func TestTimelineOrdersNewestFirst(t *testing.T) {
	now := localNoonToday(t)
	report := model.Report{
		GeneratedAt: now,
		Score:       model.Score{Status: model.SeverityCritical},
		Metrics: model.Metrics{Kernel: &model.Kernel{Available: true, Events: []model.LogEvent{
			{Kind: "oom", Message: "older event", AgeSeconds: ageSeconds(2 * time.Hour)},
			{Kind: "oom", Message: "newer event", AgeSeconds: ageSeconds(10 * time.Minute)},
		}}},
	}
	events := collectTimelineEvents(report)
	sort.Slice(events, func(i, j int) bool { return events[i].at.After(events[j].at) })
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %#v", events)
	}
	if events[0].label != "newer event" || events[1].label != "older event" {
		t.Fatalf("expected newest first, got %#v", events)
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
