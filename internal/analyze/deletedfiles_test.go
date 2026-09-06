package analyze

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func deletedFilesReport(df *model.DeletedFiles) model.Report {
	return model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, DeletedFiles: df}}
}

func TestDeletedFilesBelowThresholdStaysSilent(t *testing.T) {
	report := deletedFilesReport(&model.DeletedFiles{Available: true, TotalBytes: 10 << 20, ProcessesScanned: 5})
	Report(&report)
	if findingByID(report, "deleted-files-open") != nil {
		t.Fatalf("unexpected finding for 10 MiB of deleted-open files: %+v", report.Findings)
	}
}

func TestDeletedFilesWarnsAboveThreshold(t *testing.T) {
	report := deletedFilesReport(&model.DeletedFiles{
		Available: true, TotalBytes: 300 << 20, ProcessesScanned: 10,
		Handles: []model.DeletedFileHandle{{PID: 42, Command: "leaky", Path: "/var/log/app.log", Bytes: 300 << 20}},
	})
	Report(&report)
	found := findingByID(report, "deleted-files-open")
	if found == nil {
		t.Fatalf("no finding for 300 MiB of deleted-open files: %+v", report.Findings)
	}
	if found.Severity != model.SeverityWarning {
		t.Fatalf("severity = %s, want warning", found.Severity)
	}
}

func TestDeletedFilesCriticalsAboveHigherThreshold(t *testing.T) {
	report := deletedFilesReport(&model.DeletedFiles{Available: true, TotalBytes: 3 << 30, ProcessesScanned: 3})
	Report(&report)
	found := findingByID(report, "deleted-files-open")
	if found == nil || found.Severity != model.SeverityCritical {
		t.Fatalf("expected critical for 3 GiB: %+v", report.Findings)
	}
}

func TestDeletedFilesUnavailableProducesNoFinding(t *testing.T) {
	report := deletedFilesReport(nil)
	Report(&report)
	if findingByID(report, "deleted-files-open") != nil {
		t.Fatalf("unexpected finding when the scan did not run: %+v", report.Findings)
	}
}
