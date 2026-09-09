package render

import (
	"strings"
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

// A successful probe can still be actionable when it is slow. These tests
// keep the summary, verbose evidence, and --quiet output tied to the
// analyzer's latency findings instead of displaying a contradictory OK row.
func TestLatencyFindingsSetDNSAndGatewayRowSeverities(t *testing.T) {
	tests := []struct {
		name       string
		report     model.Report
		row        string
		verboseRow string
	}{
		{
			name: "slow local DNS",
			report: model.Report{
				Metrics: model.Metrics{DNSResolution: &model.DNSResolution{
					Available: true,
					Local:     &model.DNSResolutionResult{Resolved: true, Domain: "example.com", Server: "192.0.2.53", LatencyMillis: 1500},
					External:  &model.DNSResolutionResult{Resolved: true, Domain: "example.com", Server: "1.1.1.1", LatencyMillis: 20},
				}},
				Findings: []model.Finding{{ID: "dns-resolution-local-slow", Severity: model.SeverityWarning}},
			},
			row:        "DNS resolution WARN",
			verboseRow: "Local resolution WARN",
		},
		{
			name: "slow external DNS",
			report: model.Report{
				Metrics: model.Metrics{DNSResolution: &model.DNSResolution{
					Available: true,
					Local:     &model.DNSResolutionResult{Resolved: true, Domain: "example.com", Server: "192.0.2.53", LatencyMillis: 20},
					External:  &model.DNSResolutionResult{Resolved: true, Domain: "example.com", Server: "1.1.1.1", LatencyMillis: 3200},
				}},
				Findings: []model.Finding{{ID: "dns-resolution-external-slow", Severity: model.SeverityCritical}},
			},
			row:        "DNS resolution CRIT",
			verboseRow: "External resolution CRIT",
		},
		{
			name: "high gateway latency",
			report: model.Report{
				Metrics:  model.Metrics{GatewayCheck: &model.GatewayCheck{Available: true, Gateway: "192.0.2.1", Sent: 3, Received: 3, AvgLatencyMillis: 600}},
				Findings: []model.Finding{{ID: "gateway-high-latency", Severity: model.SeverityCritical}},
			},
			row:        "Gateway CRIT",
			verboseRow: "Latency CRIT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, options := range []Options{{ASCII: true}, {ASCII: true, Quiet: true}, {ASCII: true, Verbose: true}} {
				var out strings.Builder
				Write(&out, tt.report, options)
				text := out.String()
				if !strings.Contains(text, tt.row) {
					t.Fatalf("%+v output missing actionable latency row %q:\n%s", options, tt.row, text)
				}
				if options.Verbose && !strings.Contains(text, tt.verboseRow) {
					t.Fatalf("verbose output missing matching evidence severity %q:\n%s", tt.verboseRow, text)
				}
			}
		})
	}
}
