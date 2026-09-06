package analyze

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func systemdReport(units []model.SystemdUnitRestart) model.Report {
	return model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Systemd: &model.Systemd{Available: true, RestartingUnits: units}}}
}

// The scenario from real testing: `systemd-run --property=Restart=always
// --property=RestartSec=1 /bin/false` restarts far more than 3 times within
// any few-second sample.
func TestSystemdCrashLoopIsCritical(t *testing.T) {
	report := systemdReport([]model.SystemdUnitRestart{{Unit: "glimpse-crashloop.service", RestartsDelta: 4}})
	Report(&report)
	found := findingByID(report, "systemd-restarting-glimpse-crashloop.service")
	if found == nil {
		t.Fatalf("no finding for a unit that restarted 4 times during the sample: %+v", report.Findings)
	}
	if found.Severity != model.SeverityCritical {
		t.Fatalf("severity = %s, want critical", found.Severity)
	}
}

func TestSystemdSingleRestartIsWarning(t *testing.T) {
	report := systemdReport([]model.SystemdUnitRestart{{Unit: "flaky.service", RestartsDelta: 1}})
	Report(&report)
	found := findingByID(report, "systemd-restarting-flaky.service")
	if found == nil || found.Severity != model.SeverityWarning {
		t.Fatalf("expected a warning for one restart during the sample: %+v", report.Findings)
	}
}

func TestSystemdNoRestartsStaysSilent(t *testing.T) {
	report := systemdReport(nil)
	Report(&report)
	for _, f := range report.Findings {
		if f.Category == "services" && f.ID != "failed-units" {
			t.Fatalf("unexpected services finding with no restarting units: %+v", f)
		}
	}
}

// A unit can be restarting (Restart=always keeps it out of "active/failed"
// long enough for systemd to still call it running) without ever appearing
// in FailedUnits; the two findings are independent and both may fire.
func TestSystemdRestartLoopIndependentOfFailedUnits(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Systemd: &model.Systemd{
		Available:       true,
		FailedUnits:     nil,
		RestartingUnits: []model.SystemdUnitRestart{{Unit: "crashloop.service", RestartsDelta: 10}},
	}}}
	Report(&report)
	if findingByID(report, "failed-units") != nil {
		t.Fatalf("did not expect a failed-units finding: %+v", report.Findings)
	}
	if findingByID(report, "systemd-restarting-crashloop.service") == nil {
		t.Fatalf("expected the restart-loop finding to fire independently of failed-units: %+v", report.Findings)
	}
}
