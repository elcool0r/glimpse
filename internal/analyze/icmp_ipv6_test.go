package analyze

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func icmpReport(check *model.ICMPCheck) model.Report {
	return model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, ICMPCheck: check}}
}

func TestICMPExternalNoReplyIsInformational(t *testing.T) {
	report := icmpReport(&model.ICMPCheck{Available: true, Target: "1.1.1.1", Sent: 3, Received: 0, PacketLossPct: 100})
	Report(&report)
	found := findingByID(report, "icmp-external-unreachable")
	if found == nil || found.Severity != model.SeverityInfo {
		t.Fatalf("expected an informational finding when ICMP is fully blocked: %+v", report.Findings)
	}
}

func TestICMPExternalPacketLossIsWarning(t *testing.T) {
	report := icmpReport(&model.ICMPCheck{Available: true, Target: "1.1.1.1", Sent: 4, Received: 1, PacketLossPct: 75})
	Report(&report)
	found := findingByID(report, "icmp-external-packet-loss")
	if found == nil || found.Severity != model.SeverityWarning {
		t.Fatalf("expected a warning for 75%% loss: %+v", report.Findings)
	}
}

func TestICMPExternalHealthyStaysSilent(t *testing.T) {
	report := icmpReport(&model.ICMPCheck{Available: true, Target: "1.1.1.1", Sent: 3, Received: 3, AvgLatencyMillis: 10})
	Report(&report)
	for _, id := range []string{"icmp-external-unreachable", "icmp-external-packet-loss", "icmp-external-high-latency"} {
		if findingByID(report, id) != nil {
			t.Fatalf("unexpected finding %s for a healthy probe", id)
		}
	}
}

func TestICMPExternalHighLatencyEscalates(t *testing.T) {
	warn := icmpReport(&model.ICMPCheck{Available: true, Target: "1.1.1.1", Sent: 3, Received: 3, AvgLatencyMillis: 400})
	Report(&warn)
	if found := findingByID(warn, "icmp-external-high-latency"); found == nil || found.Severity != model.SeverityWarning {
		t.Fatalf("expected warning at 400ms: %+v", warn.Findings)
	}

	crit := icmpReport(&model.ICMPCheck{Available: true, Target: "1.1.1.1", Sent: 3, Received: 3, AvgLatencyMillis: 900})
	Report(&crit)
	if found := findingByID(crit, "icmp-external-high-latency"); found == nil || found.Severity != model.SeverityCritical {
		t.Fatalf("expected critical at 900ms: %+v", crit.Findings)
	}
}

func ipv6Report(check *model.IPv6Check) model.Report {
	return model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, IPv6Check: check}}
}

func TestIPv6UnreachableIsWarning(t *testing.T) {
	report := ipv6Report(&model.IPv6Check{Available: true, Target: "2606:4700:4700::1111", Sent: 3, Received: 0, PacketLossPct: 100})
	Report(&report)
	found := findingByID(report, "ipv6-unreachable")
	if found == nil || found.Severity != model.SeverityWarning {
		t.Fatalf("expected a warning finding when IPv6 ICMP is fully blocked: %+v", report.Findings)
	}
}

func TestIPv6HealthyStaysSilent(t *testing.T) {
	report := ipv6Report(&model.IPv6Check{Available: true, Target: "2606:4700:4700::1111", Sent: 3, Received: 3})
	Report(&report)
	for _, id := range []string{"ipv6-unreachable", "ipv6-packet-loss"} {
		if findingByID(report, id) != nil {
			t.Fatalf("unexpected finding %s for a healthy IPv6 probe", id)
		}
	}
}

func TestIPv6NotConfiguredProducesNoFinding(t *testing.T) {
	report := ipv6Report(nil)
	Report(&report)
	for _, id := range []string{"ipv6-unreachable", "ipv6-packet-loss"} {
		if findingByID(report, id) != nil {
			t.Fatalf("unexpected finding %s when the probe did not run (IPv4-only host)", id)
		}
	}
}
