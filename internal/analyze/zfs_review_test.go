package analyze

import (
	"strings"
	"testing"

	"github.com/elcool0r/glimpse/internal/collect/zfs"
	"github.com/elcool0r/glimpse/internal/model"
)

func TestZFSLeafErrorsFlowIntoOneFinding(t *testing.T) {
	pools := zfs.ParseStatus("pool: tank\n state: ONLINE\nconfig:\n tank ONLINE 0 0 0\n /dev/sda ONLINE 0 0 7\nerrors: No known data errors\n")
	r := model.Report{Metrics: model.Metrics{ZFSPools: pools}}
	Report(&r)
	if len(r.Findings) != 1 || r.Findings[0].ID != "zfs-pool-tank-io-errors" || r.Findings[0].Severity != model.SeverityWarning || !strings.Contains(r.Findings[0].Summary, "/dev/sda") {
		t.Fatalf("findings=%+v", r.Findings)
	}
}

func TestZFSRepeatedHierarchyRowsRemainOnePoolFinding(t *testing.T) {
	r := model.Report{Metrics: model.Metrics{ZFSPools: []model.ZFSPool{{Name: "tank", Health: "ONLINE", VdevErrors: []model.ZFSVdevError{
		{Name: "mirror-0", State: "DEGRADED", ReadErrors: 5},
		{Name: "/dev/sda", State: "ONLINE", ReadErrors: 5},
	}}}}}
	Report(&r)
	if len(r.Findings) != 1 || r.Findings[0].ScoreImpact != 15 {
		t.Fatalf("repeated hierarchy produced duplicate/incorrect finding: %+v", r.Findings)
	}
}
