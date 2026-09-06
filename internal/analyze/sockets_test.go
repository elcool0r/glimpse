package analyze

import (
	"strings"
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func socketReport(tcp *model.TCP, resources *model.Resources, ct *model.Conntrack) model.Report {
	return model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, TCP: tcp, Resources: resources, Conntrack: ct}}
}

// A drop already happened, so unlike a utilization warning it is not a
// prediction. It must fire even when the table looks calm, which is exactly
// the case a burst produces.
func TestConntrackDropsWarnIndependentlyOfUtilization(t *testing.T) {
	report := socketReport(nil, &model.Resources{Conntrack: 100, ConntrackMaximum: 262144}, &model.Conntrack{Drops: 12})
	Report(&report)
	found := findingByID(report, "conntrack-drops")
	if found == nil {
		t.Fatalf("no conntrack drop finding: %+v", report.Findings)
	}
	if found.Severity != model.SeverityWarning {
		t.Fatalf("severity = %s, want warning", found.Severity)
	}
	// The capacity rule must stay quiet: 100 of 262144 is not exhaustion.
	if f := findingByID(report, "resource-conntrack"); f != nil {
		t.Fatalf("utilization rule fired on an idle table: %+v", f)
	}
}

func TestNoConntrackDropsStaysSilent(t *testing.T) {
	report := socketReport(nil, nil, &model.Conntrack{})
	Report(&report)
	if f := findingByID(report, "conntrack-drops"); f != nil {
		t.Fatalf("unexpected finding with zero drops: %+v", f)
	}
}

// Socket tables are judgeable only because the kernel publishes a ceiling. With
// no ceiling known the rule must stay silent rather than invent a threshold.
func TestSocketTableSaturation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tcp       model.TCP
		resources model.Resources
		id        string
		want      bool
	}{
		{"time-wait saturated", model.TCP{TimeWaitSockets: 125000}, model.Resources{TimeWaitMaximum: 131072}, "tcp-time-wait-saturation", true},
		{"time-wait healthy", model.TCP{TimeWaitSockets: 4000}, model.Resources{TimeWaitMaximum: 131072}, "tcp-time-wait-saturation", false},
		{"time-wait no ceiling", model.TCP{TimeWaitSockets: 125000}, model.Resources{}, "tcp-time-wait-saturation", false},
		{"orphans saturated", model.TCP{OrphanSockets: 31000}, model.Resources{OrphanMaximum: 32768}, "tcp-orphan-saturation", true},
		{"orphans healthy", model.TCP{OrphanSockets: 12}, model.Resources{OrphanMaximum: 32768}, "tcp-orphan-saturation", false},
	} {
		tcp, resources := tc.tcp, tc.resources
		report := socketReport(&tcp, &resources, nil)
		Report(&report)
		if got := findingByID(report, tc.id) != nil; got != tc.want {
			t.Errorf("%s: finding %s = %v, want %v", tc.name, tc.id, got, tc.want)
		}
	}
}

// The overflow count alone tells the reader something is wrong but not what to
// change. somaxconn is the ceiling every listener's backlog is capped to, so
// naming it is what makes the finding actionable.
func TestListenOverflowNamesTheBacklogCeiling(t *testing.T) {
	tcp := model.TCP{ListenOverflows: 3, ListenDrops: 1}
	report := socketReport(&tcp, &model.Resources{ListenBacklogMaximum: 4096}, nil)
	Report(&report)
	found := findingByID(report, "tcp-listen-overflow")
	if found == nil {
		t.Fatalf("no listen overflow finding: %+v", report.Findings)
	}
	if !strings.Contains(found.Summary, "somaxconn is 4096") {
		t.Fatalf("summary omits the ceiling: %q", found.Summary)
	}

	// Where the ceiling could not be read, the finding still stands on its own
	// rather than printing a zero.
	bare := socketReport(&tcp, nil, nil)
	Report(&bare)
	found = findingByID(bare, "tcp-listen-overflow")
	if found == nil {
		t.Fatal("finding disappeared without resources")
	}
	if strings.Contains(found.Summary, "somaxconn") {
		t.Fatalf("summary invented a ceiling: %q", found.Summary)
	}
}
