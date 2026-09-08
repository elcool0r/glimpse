package analyze

import (
	"strings"
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func pathMTUReport(check *model.PathMTUCheck) model.Report {
	return model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, PathMTUCheck: check}}
}

func TestPathMTUNoTestedDFRepliesWarns(t *testing.T) {
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
		t.Fatalf("should not also fire the reduced-size finding: %+v", report.Findings)
	}
	assertPathMTUFindingIsObservational(t, *found)
}

func TestPathMTUReducedDFReplyIsInfo(t *testing.T) {
	report := pathMTUReport(&model.PathMTUCheck{Available: true, Target: "1.1.1.1", CeilingMTU: 1500, FloorMTU: 576, BaselineOK: true, DiscoveredMTU: 1420})
	Report(&report)
	found := findingByID(report, "path-mtu-reduced")
	if found == nil {
		t.Fatalf("no finding when a smaller size was discovered: %+v", report.Findings)
	}
	if found.Severity != model.SeverityInfo {
		t.Fatalf("severity = %s, want info", found.Severity)
	}
	if findingByID(report, "path-mtu-blackhole") != nil {
		t.Fatalf("should not also fire the black-hole finding: %+v", report.Findings)
	}
	assertPathMTUFindingIsObservational(t, *found)
	if !strings.Contains(found.Title+found.Summary, "Largest tested IPv4 DF echo reply") && !strings.Contains(found.Title+found.Summary, "larger tested sizes") {
		t.Fatalf("finding lacks tested-probe wording: %+v", found)
	}
}

func TestPathMTUNoReplyFindingDistinguishesObservedFeedback(t *testing.T) {
	without := pathMTUReport(&model.PathMTUCheck{Available: true, Target: "1.1.1.1", CeilingMTU: 1500, FloorMTU: 576, BaselineOK: true})
	with := pathMTUReport(&model.PathMTUCheck{Available: true, Target: "1.1.1.1", CeilingMTU: 1500, FloorMTU: 576, BaselineOK: true, PacketTooBigFeedback: true})
	Report(&without)
	Report(&with)
	a, b := findingByID(without, "path-mtu-blackhole"), findingByID(with, "path-mtu-blackhole")
	if a == nil || b == nil || !strings.Contains(a.Summary, "No packet-too-big feedback was observed") || !strings.Contains(b.Summary, "Packet-too-big feedback was observed") {
		t.Fatalf("feedback evidence not distinguished: without=%+v with=%+v", a, b)
	}
	assertPathMTUFindingIsObservational(t, *a)
	assertPathMTUFindingIsObservational(t, *b)
}

func assertPathMTUFindingIsObservational(t *testing.T, found model.Finding) {
	t.Helper()
	text := strings.ToLower(found.Title + " " + found.Summary + " " + found.Suggestion)
	for _, forbidden := range []string{"pmtud", "functioning correctly", "healthy", "cleanly discovered", "path mtu is", "feedback was filtered"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("finding makes unsupported claim %q: %+v", forbidden, found)
		}
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

func TestHTTPCheckBothFailIsWarning(t *testing.T) {
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
	if found.Severity != model.SeverityWarning {
		t.Fatalf("severity = %s, want warning", found.Severity)
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

func TestHTTPCheckProxyUseIsInformational(t *testing.T) {
	report := httpCheckReport(&model.HTTPCheck{
		Available: true,
		HTTP:      &model.HTTPCheckResult{URL: "http://example.com/", Succeeded: true, ProxyUsed: true},
		HTTPS:     &model.HTTPCheckResult{URL: "https://example.com/", Succeeded: true},
	})
	Report(&report)
	found := findingByID(report, "http-check-proxy-used")
	if found == nil || found.Severity != model.SeverityInfo {
		t.Fatalf("expected informational proxy finding: %+v", report.Findings)
	}
}
