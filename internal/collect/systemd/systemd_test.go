package systemd

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

func TestParseFailedUnits(t *testing.T) {
	input := `  UNIT                 LOAD   ACTIVE SUB    DESCRIPTION
  foo.service          loaded failed failed Foo service
  zed.mount            loaded failed failed Zed mount

2 loaded units listed.`
	if got, want := ParseFailedUnits(input), []string{"foo.service", "zed.mount"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestUnavailableSystemctlIsNotAnError(t *testing.T) {
	c := New()
	c.lookPath = func(string) (string, error) { return "", errors.New("missing") }
	data, err := c.Collect(context.Background())
	if err != nil || data.Systemd == nil || data.Systemd.Available {
		t.Fatalf("data=%#v err=%v", data, err)
	}
}

func TestParseUnitNames(t *testing.T) {
	input := `  crashloop.service    loaded activating auto-restart Crash Loop
  sshd.service         loaded active    running       OpenSSH
  network.target       loaded active    active        Network`
	got := parseUnitNames(input)
	want := []string{"crashloop.service", "sshd.service"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestParseRestarts(t *testing.T) {
	input := "Id=crashloop.service\nNRestarts=304\n\nId=sshd.service\nNRestarts=0\n\n"
	got := parseRestarts(input)
	want := map[string]uint64{"crashloop.service": 304, "sshd.service": 0}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// A restart counter belongs to the block it appears in; a stray NRestarts
// line before any Id= line (malformed or unexpected output) must not be
// attributed to the previous unit.
func TestParseRestartsIgnoresOrphanedValue(t *testing.T) {
	got := parseRestarts("NRestarts=5\n\nId=real.service\nNRestarts=1\n")
	if len(got) != 1 || got["real.service"] != 1 {
		t.Fatalf("got %#v, want only real.service=1", got)
	}
}

func TestParseActiveEnterTimestamps(t *testing.T) {
	when := time.Date(2026, 1, 6, 8, 12, 45, 0, time.Local)
	input := "Id=nginx.service\nActiveEnterTimestamp=" + when.Format(activeEnterLayout) + " UTC\n\n" +
		"Id=never-started.service\nActiveEnterTimestamp=\n\n"
	got := parseActiveEnterTimestamps(input)
	if len(got) != 1 {
		t.Fatalf("got %#v, want exactly one parsed timestamp", got)
	}
	if !got["nginx.service"].Equal(when) {
		t.Fatalf("got %v, want %v", got["nginx.service"], when)
	}
}

func TestParseUnitTimestamps(t *testing.T) {
	when := time.Date(2026, 9, 8, 10, 43, 2, 0, time.Local)
	input := "Id=glimpse-test-failure.service\nStateChangeTimestamp=" + when.Format(activeEnterLayout) + " CEST\n\n"
	got := parseUnitTimestamps(input, "StateChangeTimestamp")
	if len(got) != 1 || !got["glimpse-test-failure.service"].Equal(when) {
		t.Fatalf("got %#v, want the parsed state-change timestamp", got)
	}
}

// A restart counter or timestamp belongs to the block it appears in; a
// stray value before any Id= line must not be attributed to anything.
func TestParseActiveEnterTimestampsIgnoresOrphanedValue(t *testing.T) {
	got := parseActiveEnterTimestamps("ActiveEnterTimestamp=Tue 2026-01-06 08:12:45 UTC\n\nId=real.service\n")
	if len(got) != 0 {
		t.Fatalf("got %#v, want none", got)
	}
}

func TestRecentUnitStartsFiltersToTheLookbackWindow(t *testing.T) {
	now := time.Date(2026, 1, 6, 12, 0, 0, 0, time.UTC)
	activeEnter := map[string]time.Time{
		"today.service":     now.Add(-2 * time.Hour),
		"yesterday.service": now.Add(-25 * time.Hour),
		"future.service":    now.Add(time.Hour), // defensive: a clock step during collection
	}
	got := recentUnitStarts(activeEnter, now)
	if len(got) != 1 || got[0].Unit != "today.service" {
		t.Fatalf("got %#v, want only today.service", got)
	}
}

func TestRecentUnitStartsOrdersNewestFirst(t *testing.T) {
	now := time.Date(2026, 1, 6, 12, 0, 0, 0, time.UTC)
	got := recentUnitStarts(map[string]time.Time{
		"older": now.Add(-2 * time.Hour),
		"newer": now.Add(-10 * time.Minute),
	}, now)
	if len(got) != 2 || got[0].Unit != "newer" || got[1].Unit != "older" {
		t.Fatalf("got %#v, want newer before older", got)
	}
}

// The real-world bug: a restart that happened before glimpse ran (so
// RestartsDelta during this sample is zero) must still be visible via the
// unit's own ActiveEnterTimestamp, not silently dropped.
func TestCollectPopulatesRecentStartsFromActiveEnterTimestamp(t *testing.T) {
	recent := time.Now().Add(-5 * time.Minute)
	c := &Collector{
		lookPath: func(string) (string, error) { return "/bin/systemctl", nil },
		run: fakeSystemctl(t, "", "systemd-resolved.service loaded active running DNS\n",
			"Id=systemd-resolved.service\nNRestarts=1\nActiveEnterTimestamp="+recent.Format(activeEnterLayout)+" UTC\n\n"),
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(data.Systemd.RecentStarts) != 1 || data.Systemd.RecentStarts[0].Unit != "systemd-resolved.service" {
		t.Fatalf("expected a recent start for systemd-resolved.service: %+v", data.Systemd.RecentStarts)
	}
}

func TestCollectPopulatesFailedUnitStateChangeTime(t *testing.T) {
	when := time.Date(2026, 9, 8, 10, 43, 2, 0, time.Local)
	c := &Collector{
		lookPath: func(string) (string, error) { return "/bin/systemctl", nil },
		run: fakeSystemctl(t,
			"glimpse-test-failure.service loaded failed failed /bin/false\n",
			"glimpse-test-failure.service loaded failed failed /bin/false\n",
			"Id=glimpse-test-failure.service\nStateChangeTimestamp="+when.Format(activeEnterLayout)+" CEST\n\n"),
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if got := data.Systemd.FailedUnitSince["glimpse-test-failure.service"]; !got.Equal(when) {
		t.Fatalf("got failed-unit time %v, want %v", got, when)
	}
}

func fakeSystemctl(t *testing.T, failed, listUnits, show string) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch {
		case len(args) > 0 && args[0] == "--failed":
			return []byte(failed), nil
		case len(args) > 0 && args[0] == "list-units":
			return []byte(listUnits), nil
		case len(args) > 0 && args[0] == "show":
			return []byte(show), nil
		}
		t.Fatalf("unexpected systemctl invocation: %v", args)
		return nil, nil
	}
}

func TestCollectPopulatesRestartSnapshot(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "/bin/systemctl", nil },
		run: fakeSystemctl(t, "", "crashloop.service loaded activating auto-restart Crash Loop\n",
			"Id=crashloop.service\nNRestarts=5\n\n"),
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if !data.Systemd.Available {
		t.Fatalf("expected systemd available: %+v", data.Systemd)
	}
	snap, ok := data.Snapshot.(snapshot)
	if !ok || snap.restarts["crashloop.service"] != 5 {
		t.Fatalf("unexpected snapshot: %+v", data.Snapshot)
	}
}

func TestCollectReportsBoundedRestartCoverage(t *testing.T) {
	var units strings.Builder
	for i := 0; i < maxUnits+1; i++ {
		fmt.Fprintf(&units, "service-%03d.service loaded active running Service\n", i)
	}
	c := &Collector{
		lookPath: func(string) (string, error) { return "/bin/systemctl", nil },
		run:      fakeSystemctl(t, "", units.String(), ""),
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	got := data.Systemd
	if got.ServiceUnitsDiscovered != maxUnits+1 || got.ServiceUnitsInspected != maxUnits || !got.ServiceUnitScanLimited {
		t.Fatalf("coverage=%+v", got)
	}
}

func TestDeltaReportsRestartsDuringWindow(t *testing.T) {
	c := &Collector{}
	first := collect.Data{Snapshot: snapshot{restarts: map[string]uint64{"crashloop.service": 100, "stable.service": 3}}}
	last := collect.Data{
		Systemd:  &model.Systemd{Available: true},
		Snapshot: snapshot{restarts: map[string]uint64{"crashloop.service": 104, "stable.service": 3}},
	}
	out, err := c.Delta(first, last)
	if err != nil {
		t.Fatalf("Delta returned error: %v", err)
	}
	if len(out.Systemd.RestartingUnits) != 1 {
		t.Fatalf("expected exactly one restarting unit, got %+v", out.Systemd.RestartingUnits)
	}
	got := out.Systemd.RestartingUnits[0]
	if got.Unit != "crashloop.service" || got.RestartsDelta != 4 {
		t.Fatalf("unexpected restart entry: %+v", got)
	}
}

// A unit that appeared during the window (not present at baseline) has no
// interval to compare and must not be reported.
func TestDeltaIgnoresUnitsMissingFromBaseline(t *testing.T) {
	c := &Collector{}
	first := collect.Data{Snapshot: snapshot{restarts: map[string]uint64{}}}
	last := collect.Data{
		Systemd:  &model.Systemd{Available: true},
		Snapshot: snapshot{restarts: map[string]uint64{"new.service": 1}},
	}
	out, err := c.Delta(first, last)
	if err != nil {
		t.Fatalf("Delta returned error: %v", err)
	}
	if len(out.Systemd.RestartingUnits) != 0 {
		t.Fatalf("expected no restarting units for a unit absent at baseline, got %+v", out.Systemd.RestartingUnits)
	}
}

// A counter that went backwards (systemd reloaded, resetting tracked state)
// is not a clean delta and must not be reported as a negative/wrapped count.
func TestDeltaIgnoresCounterGoingBackwards(t *testing.T) {
	c := &Collector{}
	first := collect.Data{Snapshot: snapshot{restarts: map[string]uint64{"svc.service": 10}}}
	last := collect.Data{
		Systemd:  &model.Systemd{Available: true},
		Snapshot: snapshot{restarts: map[string]uint64{"svc.service": 2}},
	}
	out, err := c.Delta(first, last)
	if err != nil {
		t.Fatalf("Delta returned error: %v", err)
	}
	if len(out.Systemd.RestartingUnits) != 0 {
		t.Fatalf("expected no restarting units when the counter decreased, got %+v", out.Systemd.RestartingUnits)
	}
}

func TestDeltaWithoutBaselineIsNotAnError(t *testing.T) {
	c := &Collector{}
	out, err := c.Delta(collect.Data{}, collect.Data{Systemd: &model.Systemd{Available: true}})
	if err != nil {
		t.Fatalf("Delta returned error: %v", err)
	}
	if len(out.Systemd.RestartingUnits) != 0 {
		t.Fatalf("expected no restarting units without a snapshot baseline, got %+v", out.Systemd.RestartingUnits)
	}
}
