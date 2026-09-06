package analyze

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func TestBacklogFindingsDetectDegradedStorageAndSecurityEvidence(t *testing.T) {
	swappiness := uint64(90)
	failedAuth := uint64(6)
	report := model.Report{Metrics: model.Metrics{
		Memory:       &model.Memory{AvailableFraction: .05, Swappiness: &swappiness, SwapInBytes: 1, PageFaults: 200000, MajorFaults: 2000},
		SoftwareRAID: []model.SoftwareRAID{{Device: "/dev/md0", State: "degraded"}},
		MountChecks:  []model.MountCheck{{MountPoint: "/backup", ActiveKnown: true}},
		Security:     &model.Security{FailedAuthAttempts: &failedAuth},
		Hardware:     &model.HardwareErrors{Available: true, Controllers: []model.HardwareErrorController{{Name: "mc0", UncorrectableErrors: 1}}},
	}}
	findings := backlogFindings(&report)
	wanted := map[string]bool{
		"memory-swappiness":          false,
		"memory-fault-pressure":      false,
		"raid-/dev/md0":              false,
		"mount-missing-/backup":      false,
		"security-failed-auth":       false,
		"hardware-uncorrectable-mc0": false,
	}
	for _, finding := range findings {
		if _, ok := wanted[finding.ID]; ok {
			wanted[finding.ID] = true
		}
	}
	for id, found := range wanted {
		if !found {
			t.Errorf("missing finding %q in %#v", id, findings)
		}
	}
}

func TestNetworkStateDoesNotWarnWhenRoutesWereNotChecked(t *testing.T) {
	findings := networkStateFindings(&model.NetworkState{Available: true})
	if len(findings) != 0 {
		t.Fatalf("unexpected finding without route coverage: %#v", findings)
	}
}
