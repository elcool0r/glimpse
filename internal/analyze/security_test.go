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
	// CPU vulnerability status is fixed for the life of the running kernel and
	// microcode and is not actionable from this host, so it is evidence rather
	// than a warning: reporting it as a warning made glimpse exit 1 on every
	// run on a great many well-maintained hosts. SELinux being loaded but not
	// enforcing is host configuration the operator can change, so it stays a
	// warning -- and carries a score impact, because severity drives the exit
	// code and a warning that never moves the score makes the two disagree.
	if got["security-reboot-required"] != model.SeverityInfo || got["security-kernel-tainted"] != model.SeverityInfo || got["security-selinux-permissive"] != model.SeverityWarning || got["security-vulnerability-retbleed"] != model.SeverityInfo {
		t.Fatalf("unexpected severities: %+v", got)
	}
	if offenders := ActionableWithoutImpact(findings); len(offenders) > 0 {
		t.Fatalf("actionable findings with no score impact: %v", offenders)
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
