package systemd

import (
	"context"
	"errors"
	"reflect"
	"testing"

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
