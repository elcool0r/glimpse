package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/model"
)

func containerReport(events []model.LogEvent) model.Report {
	return model.Report{Metrics: model.Metrics{
		CPU: &model.CPU{},
		Containers: []model.ContainerRuntime{{Runtime: "docker", Containers: []model.Container{
			{ID: "abc", Name: "web", State: "running", LogEvents: events},
		}}},
	}}
}

// Healthy production log lines that contain the words "error" or "failed".
// Treating these as failures made the exit code meaningless on any host that
// runs containers, which is most of them.
func TestBenignLogWordingDoesNotWarn(t *testing.T) {
	benign := []model.LogEvent{
		{Kind: "error", Message: `10.0.0.4 - - "GET /api/v1/error-budget HTTP/1.1" 200 3ms`},
		{Kind: "error", Message: "DEBUG loaded module github.com/pkg/errors v0.9.1"},
		{Kind: "error", Message: "INFO retry succeeded after transient error"},
		{Kind: "failure", Message: "INFO health check failed once, now healthy"},
		{Kind: "failure", Message: "INFO failure injection disabled"},
	}
	report := containerReport(benign)
	Report(&report)
	if report.Score.Status == model.SeverityWarning || report.Score.Status == model.SeverityCritical {
		t.Fatalf("benign log wording produced %s: %+v", report.Score.Status, report.Findings)
	}
	if report.Score.Value != 100 {
		t.Fatalf("benign log wording cost score: %d", report.Score.Value)
	}
	var kept bool
	for _, f := range report.Findings {
		if f.Severity == model.SeverityInfo && strings.Contains(f.ID, "log-messages") {
			kept = true
		}
	}
	if !kept {
		t.Fatal("generic log evidence should remain visible, just not as a verdict")
	}
}

// The concrete signatures must still warn: tightening the generic rules must
// not gut detection.
func TestConcreteLogFailuresStillWarn(t *testing.T) {
	for _, kind := range []string{"oom", "panic", "segmentation_fault", "uncaught_exception", "data_corruption", "read_only_filesystem"} {
		report := containerReport([]model.LogEvent{{Kind: kind, Message: kind + " evidence"}})
		Report(&report)
		if report.Score.Status != model.SeverityWarning {
			t.Fatalf("%s did not warn: %+v", kind, report.Findings)
		}
	}
}

// Attribute strings are positional bit fields whose case is significant.
// Matching them as a character set flagged healthy snapshot and origin volumes.
func TestLVMFindingsFollowCollectorVerdict(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, LVM: &model.LVM{LogicalVolumes: []model.LVMLogicalVolume{
		{Name: "snap", Group: "vg0", Attr: "swi-a-s---"},
		{Name: "root", Group: "vg0", Attr: "-wi-ao----"},
	}}}}
	Report(&report)
	if len(report.Findings) != 0 {
		t.Fatalf("healthy volumes produced findings: %+v", report.Findings)
	}
	report.Metrics.LVM.LogicalVolumes[0].NeedsReview = true
	report.Metrics.LVM.LogicalVolumes[0].ReviewReason = "suspended"
	Report(&report)
	if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Summary, "suspended") {
		t.Fatalf("collector verdict not surfaced: %+v", report.Findings)
	}
}

// A modern CPU boosting to within a few degrees of Tjmax is normal; only
// crossing the limit the hardware declares is a fault.
func TestThermalWarnsOnlyAtTheDeclaredLimit(t *testing.T) {
	near := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Thermal: []model.Thermal{{Name: "k10temp: Tctl", TemperatureC: 96, CriticalC: 100}}}}
	Report(&near)
	if near.Score.Status != model.SeverityInfo || near.Score.Value != 100 {
		t.Fatalf("approaching the limit warned: %+v %+v", near.Score, near.Findings)
	}
	over := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Thermal: []model.Thermal{{Name: "k10temp: Tctl", TemperatureC: 101, CriticalC: 100}}}}
	Report(&over)
	if over.Score.Status != model.SeverityWarning {
		t.Fatalf("crossing the limit did not warn: %+v", over.Findings)
	}
}

// A record from overnight should not read as urgently at noon as it did at 03:00.
func TestKernelEventSeverityFollowsRecordAge(t *testing.T) {
	age := func(d time.Duration) *float64 { v := d.Seconds(); return &v }
	recent := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Kernel: &model.Kernel{Available: true,
		Events: []model.LogEvent{{Kind: "oom", Message: "Out of memory: Killed process 99", AgeSeconds: age(2 * time.Minute)}}}}}
	Report(&recent)
	if recent.Score.Status != model.SeverityCritical {
		t.Fatalf("a current OOM must stay critical: %+v", recent.Findings)
	}
	old := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Kernel: &model.Kernel{Available: true,
		Events: []model.LogEvent{{Kind: "oom", Message: "Out of memory: Killed process 99", AgeSeconds: age(9 * time.Hour)}}}}}
	Report(&old)
	if old.Score.Status != model.SeverityWarning {
		t.Fatalf("an overnight OOM should step down, got %s: %+v", old.Score.Status, old.Findings)
	}
	if !strings.Contains(old.Findings[0].Summary, "ago") {
		t.Fatalf("age not reported: %q", old.Findings[0].Summary)
	}
}

// Without a per-category bound, a handful of findings in one subsystem floors
// the score and the EXCELLENT/GOOD/DEGRADED bands stop meaning anything.
func TestScoreImpactIsCappedPerCategory(t *testing.T) {
	var findings []model.Finding
	for i := 0; i < 6; i++ {
		findings = append(findings, model.Finding{Severity: model.SeverityCritical, Category: "zfs", ScoreImpact: 30})
	}
	score := scoreFindings(findings)
	if score.Value != 100-categoryImpactCap {
		t.Fatalf("category cap not applied: %+v", score)
	}
	findings = append(findings, model.Finding{Severity: model.SeverityWarning, Category: "memory", ScoreImpact: 12})
	if got := scoreFindings(findings); got.Value != 100-categoryImpactCap-12 {
		t.Fatalf("a second category should still subtract: %+v", got)
	}
}

// Task counts from /proc/loadavg include threads, so pid_max alone is the
// wrong ceiling to compare them against.
func TestTaskCeilingPrefersThreadsMax(t *testing.T) {
	if got := taskCeiling(&model.Resources{ProcessesMaximum: 4194304, ThreadsMaximum: 63000}); got != 63000 {
		t.Fatalf("ceiling=%d", got)
	}
	if got := taskCeiling(&model.Resources{ProcessesMaximum: 32768}); got != 32768 {
		t.Fatalf("ceiling without threads-max=%d", got)
	}
}
