package analyze

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func TestAnalyzeSecurityOnlyFlagsExplicitVulnerableStatuses(t *testing.T) {
	pending := true
	tainted := true
	report := &model.Report{Metrics: model.Metrics{Security: &model.Security{RebootRequired: &pending, KernelTainted: &tainted, KernelTaintMask: 1, SELinux: "permissive", AppArmor: "unknown", Vulnerabilities: []model.KernelVulnerability{{Name: "mds", Status: "Not affected"}, {Name: "spectre_v2", Status: "Mitigation: Retpolines"}, {Name: "retbleed", Status: "Vulnerable: unmitigated"}}}}}
	findings := AnalyzeSecurity(report)
	if len(findings) != 4 {
		t.Fatalf("got %d findings: %+v", len(findings), findings)
	}
	got := make(map[string]model.Severity, len(findings))
	for _, finding := range findings {
		got[finding.ID] = finding.Severity
	}
	if got["security-reboot-required"] != model.SeverityInfo || got["security-kernel-tainted"] != model.SeverityInfo || got["security-selinux-permissive"] != model.SeverityWarning || got["security-vulnerability-retbleed"] != model.SeverityWarning {
		t.Fatalf("unexpected severities: %+v", got)
	}
}

func TestAnalyzeSecurityHidesZFSOnlyKernelTaint(t *testing.T) {
	tainted := true
	report := &model.Report{Metrics: model.Metrics{Security: &model.Security{
		KernelTainted:      &tainted,
		KernelTaintMask:    4097,
		KernelTaintModules: []string{"spl", "zfs"},
	}}}
	for _, finding := range AnalyzeSecurity(report) {
		if finding.ID == "security-kernel-tainted" {
			t.Fatal("ZFS/SPL-only taint should be hidden from normal findings")
		}
	}
}
