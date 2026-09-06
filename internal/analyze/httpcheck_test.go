package analyze

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func pathMTUReport(check *model.PathMTUCheck) model.Report {
	return model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, PathMTUCheck: check}}
}

func TestPathMTUNoUsableSizeWarns(t *testing.T) {
	report := pathMTUReport(&model.PathMTUCheck{Available: true, Target: "1.1.1.1", CeilingMTU: 1500, FloorMTU: 576, BaselineOK: true, DiscoveredMTU: 0})
	Report(&report)
	found := findingByID(report, "path-mtu-blackhole")
	if found == nil {
		t.Fatalf("no finding when no size got through: %+v", report.Findings)
	}
	if found.Severity != model.SeverityWarning {
		t.Fatalf("severity = %s, want warning", found.Severity)
	}
	if findingByID(report, "path-mtu-reduced") != nil {
		t.Fatalf("should not also fire the reduced-but-healthy finding: %+v", report.Findings)
	}
}

func TestPathMTUReducedButDiscoveredIsInfo(t *testing.T) {
	report := pathMTUReport(&model.PathMTUCheck{Available: true, Target: "1.1.1.1", CeilingMTU: 1500, FloorMTU: 576, BaselineOK: true, DiscoveredMTU: 1420})
	Report(&report)
	found := findingByID(report, "path-mtu-reduced")
	if found == nil {
		t.Fatalf("no finding when a smaller size was discovered: %+v", report.Findings)
	}
	if found.Severity != model.SeverityInfo {
		t.Fatalf("severity = %s, want info (a discovered, working reduced MTU is healthy)", found.Severity)
	}
	if findingByID(report, "path-mtu-blackhole") != nil {
		t.Fatalf("should not also fire the black-hole finding: %+v", report.Findings)
	}
}

func TestPathMTUFullCeilingStaysSilent(t *testing.T) {
	report := pathMTUReport(&model.PathMTUCheck{Available: true, Target: "1.1.1.1", CeilingMTU: 1500, FloorMTU: 576, BaselineOK: true, DiscoveredMTU: 1500})
	Report(&report)
	for _, id := range []string{"path-mtu-blackhole", "path-mtu-reduced"} {
		if findingByID(report, id) != nil {
			t.Fatalf("unexpected finding %s when the full ceiling MTU works", id)
		}
	}
}

func TestPathMTUUnreachableAnchorStaysSilent(t *testing.T) {
	report := pathMTUReport(&model.PathMTUCheck{Available: true, Target: "1.1.1.1", BaselineOK: false, DiscoveredMTU: 0})
	Report(&report)
	if findingByID(report, "path-mtu-blackhole") != nil {
		t.Fatalf("unreachable anchor is a connectivity signal, not an MTU one: %+v", report.Findings)
	}
}

func httpCheckReport(check *model.HTTPCheck) model.Report {
	return model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, HTTPCheck: check}}
}

func TestHTTPCheckBothFailIsCritical(t *testing.T) {
	report := httpCheckReport(&model.HTTPCheck{
		Available: true,
		HTTP:      &model.HTTPCheckResult{URL: "http://example.com/", Succeeded: false, Error: "timeout"},
		HTTPS:     &model.HTTPCheckResult{URL: "https://example.com/", Succeeded: false, Error: "timeout"},
	})
	Report(&report)
	found := findingByID(report, "http-check-failed")
	if found == nil {
		t.Fatalf("no finding when both requests failed: %+v", report.Findings)
	}
	if found.Severity != model.SeverityCritical {
		t.Fatalf("severity = %s, want critical", found.Severity)
	}
}

func TestHTTPCheckHTTPSOnlyFailIsWarning(t *testing.T) {
	report := httpCheckReport(&model.HTTPCheck{
		Available: true,
		HTTP:      &model.HTTPCheckResult{URL: "http://example.com/", Succeeded: true},
		HTTPS:     &model.HTTPCheckResult{URL: "https://example.com/", Succeeded: false, Error: "tls: handshake failure"},
	})
	Report(&report)
	found := findingByID(report, "https-check-failed")
	if found == nil {
		t.Fatalf("no finding when only https failed: %+v", report.Findings)
	}
	if found.Severity != model.SeverityWarning {
		t.Fatalf("severity = %s, want warning", found.Severity)
	}
	if findingByID(report, "http-check-failed") != nil {
		t.Fatalf("should not also fire the both-failed finding: %+v", report.Findings)
	}
}

func TestHTTPCheckBothSucceedStaysSilent(t *testing.T) {
	report := httpCheckReport(&model.HTTPCheck{
		Available: true,
		HTTP:      &model.HTTPCheckResult{URL: "http://example.com/", Succeeded: true},
		HTTPS:     &model.HTTPCheckResult{URL: "https://example.com/", Succeeded: true},
	})
	Report(&report)
	for _, id := range []string{"http-check-failed", "https-check-failed", "http-check-http-failed"} {
		if findingByID(report, id) != nil {
			t.Fatalf("unexpected finding %s when both succeeded", id)
		}
	}
}
