package render

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func TestLinkSummary(t *testing.T) {
	speed := func(v uint64) *uint64 { return &v }
	for _, tc := range []struct {
		name  string
		iface model.Network
		want  string
	}{
		// A virtual interface and a down port both report no speed. Showing
		// "0 Mb/s" would read as a fault rather than as absent information.
		{"absent", model.Network{}, ""},
		{"zero", model.Network{SpeedMbps: speed(0)}, ""},
		{"sub-gigabit", model.Network{SpeedMbps: speed(100), Duplex: "full"}, " (100 Mb/s)"},
		{"gigabit", model.Network{SpeedMbps: speed(1000), Duplex: "full"}, " (1 Gb/s)"},
		{"ten-gigabit", model.Network{SpeedMbps: speed(10000), Duplex: "full"}, " (10 Gb/s)"},
		// Not a whole number of gigabits, so it stays in Mb/s rather than
		// rounding away the unusual value that made it worth reading.
		{"odd rate", model.Network{SpeedMbps: speed(2500), Duplex: "full"}, " (2500 Mb/s)"},
		// Half duplex is named because on current hardware it is nearly always
		// accidental; full duplex is the unremarkable default and stays quiet.
		{"half duplex", model.Network{SpeedMbps: speed(1000), Duplex: "half"}, " (1 Gb/s half duplex)"},
		{"unknown duplex", model.Network{SpeedMbps: speed(1000)}, " (1 Gb/s)"},
	} {
		if got := linkSummary(tc.iface); got != tc.want {
			t.Errorf("%s: linkSummary = %q, want %q", tc.name, got, tc.want)
		}
	}
}
