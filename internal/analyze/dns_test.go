package analyze

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func dnsReport(dns *model.DNSConfig, failed []string) model.Report {
	return model.Report{Metrics: model.Metrics{
		CPU:          &model.CPU{},
		NetworkState: &model.NetworkState{Available: true, DNS: dns},
		Systemd:      &model.Systemd{Available: true, FailedUnits: failed},
	}}
}

func TestNoNameserverWarns(t *testing.T) {
	report := dnsReport(&model.DNSConfig{Available: true}, nil)
	Report(&report)
	if findingByID(report, "dns-no-nameserver") == nil {
		t.Fatalf("no finding for an empty resolver config: %+v", report.Findings)
	}
}

func TestConfiguredNameserverStaysSilent(t *testing.T) {
	report := dnsReport(&model.DNSConfig{Available: true, Nameservers: []string{"1.1.1.1"}}, nil)
	Report(&report)
	if f := findingByID(report, "dns-no-nameserver"); f != nil {
		t.Fatalf("unexpected finding: %+v", f)
	}
}

// Pointing at the stub is the default on most systemd distributions. Warning
// about it on its own would fire on a healthy majority of hosts, so the rule
// requires proof that the service it depends on has actually failed.
func TestStubResolverOnlyWarnsWhenResolvedFailed(t *testing.T) {
	stub := &model.DNSConfig{Available: true, Nameservers: []string{"127.0.0.53"}, StubResolver: true}

	healthy := dnsReport(stub, nil)
	Report(&healthy)
	if f := findingByID(healthy, "dns-stub-resolver-failed"); f != nil {
		t.Fatalf("stub alone produced a finding: %+v", f)
	}

	unrelated := dnsReport(stub, []string{"nginx.service"})
	Report(&unrelated)
	if f := findingByID(unrelated, "dns-stub-resolver-failed"); f != nil {
		t.Fatalf("an unrelated failed unit produced a DNS finding: %+v", f)
	}

	broken := dnsReport(stub, []string{"systemd-resolved.service"})
	Report(&broken)
	found := findingByID(broken, "dns-stub-resolver-failed")
	if found == nil {
		t.Fatalf("no finding when the stub's service failed: %+v", broken.Findings)
	}
	if found.Severity != model.SeverityCritical {
		t.Fatalf("severity = %s, want critical", found.Severity)
	}
}

// The unit name appears with and without the .service suffix depending on how
// systemctl was asked, so matching must tolerate both.
func TestResolvedFailedMatchesUnitSpelling(t *testing.T) {
	for _, unit := range []string{"systemd-resolved.service", "systemd-resolved", "  SYSTEMD-RESOLVED.SERVICE  "} {
		if !resolvedFailed([]string{unit}) {
			t.Errorf("did not match %q", unit)
		}
	}
	for _, unit := range []string{"systemd-resolvedx.service", "resolved.service", ""} {
		if resolvedFailed([]string{unit}) {
			t.Errorf("wrongly matched %q", unit)
		}
	}
}

func resolutionReport(resolution *model.DNSResolution) model.Report {
	return model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, DNSResolution: resolution}}
}

func TestDNSResolutionBothFailIsCritical(t *testing.T) {
	report := resolutionReport(&model.DNSResolution{
		Available: true,
		Local:     &model.DNSResolutionResult{Server: "192.0.2.53", Domain: "example.com"},
		External:  &model.DNSResolutionResult{Server: "1.1.1.1", Domain: "example.com"},
	})
	Report(&report)
	found := findingByID(report, "dns-resolution-failed")
	if found == nil {
		t.Fatalf("no finding when both servers failed to resolve: %+v", report.Findings)
	}
	if found.Severity != model.SeverityCritical {
		t.Fatalf("severity = %s, want critical", found.Severity)
	}
}

func TestDNSResolutionLocalOnlyFailIsWarning(t *testing.T) {
	report := resolutionReport(&model.DNSResolution{
		Available: true,
		Local:     &model.DNSResolutionResult{Server: "192.0.2.53", Domain: "example.com", Resolved: false},
		External:  &model.DNSResolutionResult{Server: "1.1.1.1", Domain: "example.com", Resolved: true},
	})
	Report(&report)
	found := findingByID(report, "dns-resolution-local-failed")
	if found == nil {
		t.Fatalf("no finding when only the local resolver failed: %+v", report.Findings)
	}
	if found.Severity != model.SeverityWarning {
		t.Fatalf("severity = %s, want warning", found.Severity)
	}
	if findingByID(report, "dns-resolution-failed") != nil {
		t.Fatalf("should not also fire the both-failed finding: %+v", report.Findings)
	}
}

func TestDNSResolutionExternalOnlyFailIsInfo(t *testing.T) {
	report := resolutionReport(&model.DNSResolution{
		Available: true,
		Local:     &model.DNSResolutionResult{Server: "192.0.2.53", Domain: "example.com", Resolved: true},
		External:  &model.DNSResolutionResult{Server: "1.1.1.1", Domain: "example.com", Resolved: false},
	})
	Report(&report)
	found := findingByID(report, "dns-resolution-external-failed")
	if found == nil {
		t.Fatalf("no finding when only the external resolver failed: %+v", report.Findings)
	}
	if found.Severity != model.SeverityInfo {
		t.Fatalf("severity = %s, want info", found.Severity)
	}
}

func TestDNSResolutionBothSucceedIsSilent(t *testing.T) {
	report := resolutionReport(&model.DNSResolution{
		Available: true,
		Local:     &model.DNSResolutionResult{Server: "192.0.2.53", Domain: "example.com", Resolved: true},
		External:  &model.DNSResolutionResult{Server: "1.1.1.1", Domain: "example.com", Resolved: true},
	})
	Report(&report)
	for _, id := range []string{"dns-resolution-failed", "dns-resolution-local-failed", "dns-resolution-external-failed"} {
		if findingByID(report, id) != nil {
			t.Fatalf("unexpected finding %s when both resolved", id)
		}
	}
}

func TestDNSResolutionNoLocalConfiguredAndExternalFailsIsCritical(t *testing.T) {
	report := resolutionReport(&model.DNSResolution{
		Available: true,
		External:  &model.DNSResolutionResult{Server: "1.1.1.1", Domain: "example.com", Resolved: false},
	})
	Report(&report)
	found := findingByID(report, "dns-resolution-failed")
	if found == nil {
		t.Fatalf("no finding when there is no local nameserver and the external one failed too: %+v", report.Findings)
	}
	if found.Severity != model.SeverityCritical {
		t.Fatalf("severity = %s, want critical", found.Severity)
	}
}
