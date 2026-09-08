package render

import (
	"strings"
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func TestPathMTUReducedProbeRenderingIsObservational(t *testing.T) {
	report := model.Report{
		Metrics:  model.Metrics{PathMTUCheck: &model.PathMTUCheck{Available: true, Target: "1.1.1.1", CeilingMTU: 1500, FloorMTU: 576, BaselineOK: true, DiscoveredMTU: 1428}},
		Findings: []model.Finding{{ID: "path-mtu-reduced", Severity: model.SeverityInfo, Category: "network", Title: "Largest tested IPv4 DF echo reply was 1428 bytes"}},
	}
	var compact, verbose strings.Builder
	Write(&compact, report, Options{ASCII: true, Width: 200})
	Write(&verbose, report, Options{ASCII: true, Verbose: true, Width: 200})
	if strings.Contains(compact.String(), "Path MTU") {
		t.Fatalf("reduced INFO observation should remain verbose-only:\n%s", compact.String())
	}
	text := verbose.String()
	for _, want := range []string{"largest tested IPv4 DF echo reply: 1428/1500 bytes", "larger tested sizes up to 1500 bytes did not reply", "Packet-too-big feedback INFO  not observed"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	assertPathMTURenderingIsObservational(t, text)
}

func TestPathMTUNoReplyRenderingDistinguishesFeedback(t *testing.T) {
	for _, tt := range []struct {
		name     string
		feedback bool
		want     string
	}{
		{name: "silent", want: "no packet-too-big feedback observed"},
		{name: "explicit", feedback: true, want: "packet-too-big feedback observed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report := model.Report{
				Metrics:  model.Metrics{PathMTUCheck: &model.PathMTUCheck{Available: true, Target: "1.1.1.1", CeilingMTU: 1500, FloorMTU: 576, BaselineOK: true, PacketTooBigFeedback: tt.feedback}},
				Findings: []model.Finding{{ID: "path-mtu-blackhole", Severity: model.SeverityWarning, Category: "network", Title: "No IPv4 DF echo replies across tested sizes"}},
			}
			var out strings.Builder
			Write(&out, report, Options{ASCII: true, Verbose: true, Width: 200})
			text := strings.ToLower(out.String())
			if !strings.Contains(text, tt.want) {
				t.Fatalf("missing %q in:\n%s", tt.want, out.String())
			}
			assertPathMTURenderingIsObservational(t, text)
		})
	}
}

func assertPathMTURenderingIsObservational(t *testing.T, text string) {
	t.Helper()
	text = strings.ToLower(text)
	for _, forbidden := range []string{"pmtud", "functioning correctly", "healthy", "cleanly discovered", "path mtu is", "reduced but working normally"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("renderer makes unsupported claim %q:\n%s", forbidden, text)
		}
	}
}
