package analyze

import (
	"fmt"
	"strings"

	"github.com/elcool0r/glimpse/internal/model"
)

// AnalyzeSecurity returns conservative, informational observations. It does
// not infer a vulnerability from a missing interface or an unknown status.
func AnalyzeSecurity(report *model.Report) []model.Finding {
	s := report.Metrics.Security
	if s == nil {
		return nil
	}
	var findings []model.Finding
	if s.RebootRequired != nil && *s.RebootRequired {
		title := "Reboot is pending"
		if s.RebootFromPackages {
			title = "recommended Reboot is pending"
		}
		findings = append(findings, securityFinding("security-reboot-required", model.SeverityInfo, title, "The host exposes the reboot-required marker.", "Review pending package or kernel updates and reboot during the next suitable maintenance window."))
	}
	if s.KernelTainted != nil && *s.KernelTainted && !zfsTaintOnly(s) {
		findings = append(findings, securityFinding("security-kernel-tainted", model.SeverityInfo, "Kernel taint flags are set", fmt.Sprintf("The kernel taint mask is %d; this can indicate out-of-tree modules or a kernel event.", s.KernelTaintMask), "Inspect the kernel taint documentation and loaded modules before relying on kernel diagnostics."))
	}
	if s.SELinux == "permissive" {
		findings = append(findings, securityFinding("security-selinux-permissive", model.SeverityWarning, "SELinux is permissive", "SELinux is loaded but not enforcing policy.", "Confirm that permissive mode matches the host security policy."))
	}
	for _, v := range s.Vulnerabilities {
		status := strings.TrimSpace(v.Status)
		lower := strings.ToLower(status)
		if status == "" || !strings.HasPrefix(lower, "vulnerable") {
			continue
		}
		findings = append(findings, securityFinding("security-vulnerability-"+v.Name, model.SeverityWarning, "Kernel vulnerability status requires review", fmt.Sprintf("Kernel vulnerability %s reports %q.", v.Name, status), "Review the kernel vendor guidance and available updates."))
	}
	return findings
}

func zfsTaintOnly(s *model.Security) bool {
	if len(s.KernelTaintModules) == 0 {
		return false
	}
	for _, module := range s.KernelTaintModules {
		if module != "zfs" && module != "spl" {
			return false
		}
	}
	return true
}

func securityFinding(id string, severity model.Severity, title, summary, suggestion string) model.Finding {
	return model.Finding{ID: id, Severity: severity, Category: "security", Title: title, Summary: summary, Suggestion: suggestion}
}
