package analyze

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func gatewayReport(check *model.GatewayCheck) model.Report {
	return model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, GatewayCheck: check}}
}

func TestGatewayNoReplyIsCritical(t *testing.T) {
	report := gatewayReport(&model.GatewayCheck{Available: true, Gateway: "192.168.1.1", Sent: 3, Received: 0, PacketLossPct: 100})
	Report(&report)
	found := findingByID(report, "gateway-unreachable")
	if found == nil {
		t.Fatalf("no finding when the gateway never replied: %+v", report.Findings)
	}
	if found.Severity != model.SeverityCritical {
		t.Fatalf("severity = %s, want critical", found.Severity)
	}
}

func TestGatewayMajorityLossIsWarning(t *testing.T) {
	report := gatewayReport(&model.GatewayCheck{Available: true, Gateway: "192.168.1.1", Sent: 4, Received: 1, PacketLossPct: 75})
	Report(&report)
	found := findingByID(report, "gateway-packet-loss")
	if found == nil {
		t.Fatalf("no finding for 75%% packet loss: %+v", report.Findings)
	}
	if found.Severity != model.SeverityWarning {
		t.Fatalf("severity = %s, want warning", found.Severity)
	}
	if findingByID(report, "gateway-unreachable") != nil {
		t.Fatalf("should not also fire the fully-unreachable finding: %+v", report.Findings)
	}
}

func TestGatewayMinorLossStaysSilent(t *testing.T) {
	report := gatewayReport(&model.GatewayCheck{Available: true, Gateway: "192.168.1.1", Sent: 10, Received: 9, PacketLossPct: 10})
	Report(&report)
	for _, id := range []string{"gateway-unreachable", "gateway-packet-loss"} {
		if findingByID(report, id) != nil {
			t.Fatalf("unexpected finding %s for one dropped ping in ten", id)
		}
	}
}

func TestGatewayHighLatencyWarnsThenCriticals(t *testing.T) {
	warn := gatewayReport(&model.GatewayCheck{Available: true, Gateway: "192.168.1.1", Sent: 3, Received: 3, AvgLatencyMillis: 250})
	Report(&warn)
	found := findingByID(warn, "gateway-high-latency")
	if found == nil || found.Severity != model.SeverityWarning {
		t.Fatalf("expected a warning at 250ms: %+v", warn.Findings)
	}

	crit := gatewayReport(&model.GatewayCheck{Available: true, Gateway: "192.168.1.1", Sent: 3, Received: 3, AvgLatencyMillis: 600})
	Report(&crit)
	found = findingByID(crit, "gateway-high-latency")
	if found == nil || found.Severity != model.SeverityCritical {
		t.Fatalf("expected critical at 600ms: %+v", crit.Findings)
	}
}

func TestGatewayNormalLatencyStaysSilent(t *testing.T) {
	report := gatewayReport(&model.GatewayCheck{Available: true, Gateway: "192.168.1.1", Sent: 3, Received: 3, AvgLatencyMillis: 2.5})
	Report(&report)
	if findingByID(report, "gateway-high-latency") != nil {
		t.Fatalf("unexpected latency finding for a healthy LAN gateway: %+v", report.Findings)
	}
}

func TestGatewayUnavailableProducesNoFinding(t *testing.T) {
	report := gatewayReport(nil)
	Report(&report)
	for _, id := range []string{"gateway-unreachable", "gateway-packet-loss"} {
		if findingByID(report, id) != nil {
			t.Fatalf("unexpected finding %s when the probe did not run", id)
		}
	}
}
