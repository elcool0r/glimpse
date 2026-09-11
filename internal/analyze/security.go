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
			title = "Reboot is recommended by a pending package"
		}
		findings = append(findings, securityFinding("security-reboot-required", model.SeverityInfo, title, "The host exposes the reboot-required marker.", "Review pending package or kernel updates and reboot during the next suitable maintenance window.", 0))
	}
	if s.KernelTainted != nil && *s.KernelTainted && !zfsTaintOnly(s) {
		findings = append(findings, securityFinding("security-kernel-tainted", model.SeverityInfo, "Kernel taint flags are set", fmt.Sprintf("The kernel taint mask is %d; this can indicate out-of-tree modules or a kernel event.", s.KernelTaintMask), "Inspect the kernel taint documentation and loaded modules before relying on kernel diagnostics.", 0))
	}
	if s.SELinux == "permissive" {
		// A loaded-but-not-enforcing MAC policy is a host configuration the
		// operator can actually change, so it carries a real score impact:
		// severity drives the process exit code, and a warning that never
		// moves the score makes the score and the exit code disagree.
		findings = append(findings, securityFinding("security-selinux-permissive", model.SeverityWarning, "SELinux is permissive", "SELinux is loaded but not enforcing policy.", "Confirm that permissive mode matches the host security policy.", 8))
	}
	// CPU vulnerability status is posture, not a live fault: it is fixed for
	// the life of the running kernel and microcode, it is identical on every
	// run, and on current kernels a great many perfectly well-maintained hosts
	// report at least one "Vulnerable:" line that no action on this host can
	// clear. Reporting it as a Warning made glimpse exit 1 forever on those
	// hosts while still printing a 100/EXCELLENT score -- the exit code and
	// the report contradicted each other, and the scripted contract the README
	// documents became meaningless. It is reported as informational evidence
	// instead, the same treatment kernel taint already receives.
	for _, v := range s.Vulnerabilities {
		status := strings.TrimSpace(v.Status)
		lower := strings.ToLower(status)
		if status == "" || !strings.HasPrefix(lower, "vulnerable") {
			continue
		}
		findings = append(findings, securityFinding("security-vulnerability-"+v.Name, model.SeverityInfo, "Kernel vulnerability status requires review", fmt.Sprintf("Kernel vulnerability %s reports %q.", v.Name, status), "Review the kernel vendor guidance and available updates.", 0))
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

func securityFinding(id string, severity model.Severity, title, summary, suggestion string, impact int) model.Finding {
	return model.Finding{ID: id, Severity: severity, Category: "security", Title: title, Summary: summary, Suggestion: suggestion, ScoreImpact: impact}
}
