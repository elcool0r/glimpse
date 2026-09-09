package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func TestEndpointDStateFindingRendersAsInformationalObservation(t *testing.T) {
	report := model.Report{
		Metrics: model.Metrics{Processes: &model.Processes{Blocked: 1}},
		Findings: []model.Finding{{
			ID:         "process-stuck-uninterruptible",
			Severity:   model.SeverityInfo,
			Category:   "process",
			Title:      "Processes observed in uninterruptible sleep (D state) at both boundaries",
			Summary:    "1 process(es) were observed in D state at both sampling boundaries: PID 91 (tail). Endpoint observations do not establish continuous D-state residency between them.",
			Suggestion: "Inspect the affected process if the condition recurs.",
		}},
	}

	var normal bytes.Buffer
	Write(&normal, report, Options{ASCII: true, Width: 160})
	text := normal.String()
	if !strings.Contains(text, "INFO  Processes observed in uninterruptible sleep (D state) at both boundaries") {
		t.Fatalf("normal output does not expose the endpoint observation with INFO semantics:\n%s", text)
	}
	if strings.Contains(text, "WARN") || strings.Contains(text, "CRIT") {
		t.Fatalf("endpoint observation was rendered with warning or critical semantics:\n%s", text)
	}

	var verbose bytes.Buffer
	Write(&verbose, report, Options{ASCII: true, Verbose: true, Width: 160})
	if !strings.Contains(verbose.String(), "Endpoint observations do not establish continuous D-state residency") || !strings.Contains(verbose.String(), "between them.") {
		t.Fatalf("verbose output omits the endpoint evidence limitation:\n%s", verbose.String())
	}
}
