package systemd

import (
	"testing"
	"time"
)

// TestParseRestartsIgnoresPropertyOrder guards a silent, total failure mode.
// The previous readers required Id= to arrive before the property they were
// looking for; systemd promises no order within a block, so had it ever
// emitted NRestarts first, restart detection would have returned an empty map
// on every run with no error and no diagnostic to show for it.
func TestParseRestartsIgnoresPropertyOrder(t *testing.T) {
	idFirst := "Id=api.service\nNRestarts=4\n\nId=web.service\nNRestarts=1\n"
	idLast := "NRestarts=4\nId=api.service\n\nNRestarts=1\nId=web.service\n"
	interleaved := "NRestarts=4\nActiveEnterTimestamp=Mon 2024-01-01 10:00:00 UTC\nId=api.service\n\nId=web.service\nNRestarts=1\n"
	for name, output := range map[string]string{"id-first": idFirst, "id-last": idLast, "interleaved": interleaved} {
		got := parseRestarts(output)
		if got["api.service"] != 4 || got["web.service"] != 1 {
			t.Errorf("%s: parseRestarts = %v, want api=4 web=1", name, got)
		}
	}
}

func TestParseUnitTimestampsIgnoresPropertyOrder(t *testing.T) {
	output := "ActiveEnterTimestamp=Mon 2024-01-01 10:00:00 UTC\nNRestarts=2\nId=api.service\n"
	got := parseUnitTimestamps(output, "ActiveEnterTimestamp")
	at, ok := got["api.service"]
	if !ok {
		t.Fatalf("timestamp not found with Id last: %v", got)
	}
	want := time.Date(2024, 1, 1, 10, 0, 0, 0, time.Local)
	if !at.Equal(want) {
		t.Errorf("at = %s, want %s", at, want)
	}
}

// TestParseFailedUnitsKeepsUnloadableUnits covers the units the old LOAD ==
// "loaded" filter dropped: a unit whose file was removed or made invalid while
// it was failed reports LOAD=not-found (or bad-setting) with ACTIVE=failed,
// and those are exactly the ones worth surfacing.
func TestParseFailedUnitsKeepsUnloadableUnits(t *testing.T) {
	output := "" +
		"nginx.service loaded failed failed A high performance web server\n" +
		"ghost.service not-found failed failed ghost.service\n" +
		"broken.service bad-setting failed failed broken.service\n" +
		"healthy.service loaded active running fine\n" +
		"masked.service masked inactive dead masked\n"
	got := ParseFailedUnits(output)
	want := []string{"broken.service", "ghost.service", "nginx.service"}
	if len(got) != len(want) {
		t.Fatalf("ParseFailedUnits = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ParseFailedUnits = %v, want %v", got, want)
		}
	}
}
