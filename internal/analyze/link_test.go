package analyze

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func linkReport(n model.Network) model.Report {
	return model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Network: []model.Network{n}}}
}

func findingByID(report model.Report, id string) *model.Finding {
	for i := range report.Findings {
		if report.Findings[i].ID == id {
			return &report.Findings[i]
		}
	}
	return nil
}

// Frame errors and carrier losses describe the cable rather than the load, so
// they must be judged by count. Requiring a ratio against packet volume would
// hide a dying transceiver on a busy link, which is exactly when it matters.
func TestPhysicalLinkErrorsWarnByCount(t *testing.T) {
	report := linkReport(model.Network{
		Name: "eth0", RXPackets: 5_000_000, TXPackets: 5_000_000,
		RXFrameErrors: 6, TXCarrierErrors: 8,
	})
	Report(&report)
	found := findingByID(report, "network-eth0-link-errors")
	if found == nil {
		t.Fatalf("no link-error finding despite 14 physical errors: %+v", report.Findings)
	}
	if found.Severity != model.SeverityWarning {
		t.Fatalf("link errors severity = %s, want warning", found.Severity)
	}
}

// A couple of frame errors over a long sample is background noise on real
// hardware and must not produce a finding.
func TestFewPhysicalLinkErrorsStaySilent(t *testing.T) {
	report := linkReport(model.Network{Name: "eth0", RXPackets: 1000, RXFrameErrors: 2, TXCarrierErrors: 1})
	Report(&report)
	if f := findingByID(report, "network-eth0-link-errors"); f != nil {
		t.Fatalf("unexpected finding for 3 errors: %+v", f)
	}
}

// Collisions are the defining behaviour of a half-duplex segment. Warning about
// them there would fire on every host that has one, so duplex decides.
func TestCollisionsOnlyWarnOnFullDuplex(t *testing.T) {
	for _, tc := range []struct {
		duplex string
		want   bool
	}{
		{"full", true},
		{"Full", true},
		{"half", false},
		{"", false},
		{"unknown", false},
	} {
		report := linkReport(model.Network{Name: "eth0", RXPackets: 1000, Collisions: 40, Duplex: tc.duplex})
		Report(&report)
		got := findingByID(report, "network-eth0-collisions") != nil
		if got != tc.want {
			t.Fatalf("duplex %q: collision finding = %v, want %v", tc.duplex, got, tc.want)
		}
	}
}

// Overruns follow load the way drops do, so they reuse the ratio guard rather
// than firing on a raw count.
func TestOverrunsUseTheRatioGuard(t *testing.T) {
	busy := linkReport(model.Network{Name: "eth0", RXPackets: 5_000_000, RXFIFOErrors: 20})
	Report(&busy)
	if f := findingByID(busy, "network-eth0-RX-overruns"); f != nil {
		t.Fatalf("20 overruns in 5M packets should not warn: %+v", f)
	}
	saturated := linkReport(model.Network{Name: "eth0", RXPackets: 1000, RXFIFOErrors: 500})
	Report(&saturated)
	if f := findingByID(saturated, "network-eth0-RX-overruns"); f == nil {
		t.Fatalf("500 overruns in 1500 packets should warn: %+v", saturated.Findings)
	}
}
