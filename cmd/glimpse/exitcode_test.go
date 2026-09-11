//go:build linux

package main

import (
	"bytes"
	"testing"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/model"
	"github.com/elcool0r/glimpse/internal/render"
)

// TestExitCodeMatchesReportedScore is the end-to-end half of the contract the
// analyzer enforces internally: the number a script reads from $? and the
// score/label a human reads from the report must describe the same host. They
// did not -- a host with an unmitigated CPU vulnerability printed 100/
// EXCELLENT and exited 1 on every single run, which made the documented
// scripted contract meaningless on a large share of real machines.
func TestExitCodeMatchesReportedScore(t *testing.T) {
	cases := []struct {
		name    string
		metrics func(*model.Report)
		want    int
	}{
		{"clean", func(*model.Report) {}, 0},
		{"info only", func(r *model.Report) {
			r.Metrics.Filesystems = append(r.Metrics.Filesystems,
				model.Filesystem{MountPoint: "/snap/x", Type: "ext4", ReadOnly: true})
		}, 0},
		{"warning", func(r *model.Report) {
			r.Metrics.Filesystems[0].UsedFraction = .90
		}, 1},
		{"critical", func(r *model.Report) {
			r.Metrics.Filesystems[0].UsedFraction = .99
		}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			report := baseReport()
			c.metrics(&report)
			analyze.Report(&report)
			var out, errOut bytes.Buffer
			got := writeReport(&out, &errOut, report, false, false, render.Options{Width: 80})
			if got != c.want {
				t.Fatalf("exit code = %d, want %d (score %d %q/%s, findings %+v)", got, c.want, report.Score.Value, report.Score.Label, report.Score.Status, report.Findings)
			}
			// INFO is context and exits 0, so a perfect score still reads
			// EXCELLENT there. WARN and CRIT are what must not.
			if rankAtLeastWarning(report.Score.Status) && report.Score.Label == "EXCELLENT" {
				t.Fatalf("label %q contradicts status %q", report.Score.Label, report.Score.Status)
			}
			// A non-zero exit must always be explained by a score below 100;
			// that is the pairing that broke.
			if got == 1 && report.Score.Value >= 100 {
				t.Fatalf("exit 1 with a perfect score of %d", report.Score.Value)
			}
		})
	}
}

// TestVulnerableCPUStatusDoesNotFailTheRun pins the specific regression: a
// host reporting "Vulnerable:" for a CPU erratum is not a warning, because
// nothing on that host can clear it and it is identical on every run.
func TestVulnerableCPUStatusDoesNotFailTheRun(t *testing.T) {
	report := baseReport()
	report.Metrics.Security = &model.Security{Available: true, SELinux: "enforcing", Vulnerabilities: []model.KernelVulnerability{
		{Name: "spectre_v2", Status: "Vulnerable: eIBRS with unprivileged eBPF"},
		{Name: "gather_data_sampling", Status: "Vulnerable: No microcode"},
	}}
	analyze.Report(&report)
	var out, errOut bytes.Buffer
	if got := writeReport(&out, &errOut, report, false, false, render.Options{Width: 80}); got != 0 {
		t.Fatalf("exit code = %d, want 0; score %d %q/%s", got, report.Score.Value, report.Score.Label, report.Score.Status)
	}
	if report.Score.Value != 100 {
		t.Errorf("score = %d, want 100: posture evidence must not move the score either", report.Score.Value)
	}
}

func baseReport() model.Report {
	sampled := true
	return model.Report{
		SchemaVersion: model.SchemaVersion,
		Host:          model.Host{Hostname: "test", CPUCount: 4},
		Metrics: model.Metrics{
			CPU:         &model.CPU{Sampled: &sampled, HostCPUCount: 4, Utilization: .1, Load1: .2},
			Memory:      &model.Memory{Sampled: &sampled, TotalBytes: 1 << 30, AvailableFraction: .8},
			Filesystems: []model.Filesystem{{MountPoint: "/", Type: "ext4", UsedFraction: .2, TotalBytes: 1 << 30, AvailableBytes: 1 << 29}},
		},
		Collection: []model.CollectionStatus{{Collector: "cpu", Status: "ok"}},
	}
}

func rankAtLeastWarning(s model.Severity) bool {
	return s == model.SeverityWarning || s == model.SeverityCritical
}
