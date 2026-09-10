package render

import (
	"strings"
	"testing"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/model"
)

// R18: bounded and permission-limited optional scans must remain visible in
// normal and quiet output, without being converted into health findings.
func TestPartialIntegrationCoverageIsInformationalAndVisibleInQuietOutput(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{
		Systemd: &model.Systemd{
			Available: true, ServiceUnitsDiscovered: 600, ServiceUnitsInspected: 512, ServiceUnitScanLimited: true,
		},
		Containers: []model.ContainerRuntime{{
			Runtime: "docker", ContainersDiscovered: 100, ContainersInspected: 64, ContainerInspectionLimited: true,
			LogsChecked: 64, LogCandidates: 64,
		}},
		DeviceHealthCoverage: &model.DeviceHealthCoverage{
			DevicesEligible: 8, DevicesChecked: 1, Limited: true, Reason: "scan deadline",
		},
		DeletedFiles: &model.DeletedFiles{
			Available: true, ProcessesScanned: 512, ProcessesEligible: 600, ProcessScanLimited: true, ProcessesSkipped: 3,
		},
	}}

	for _, options := range []Options{{ASCII: true}, {ASCII: true, Quiet: true}} {
		var out strings.Builder
		Write(&out, report, options)
		text := out.String()
		for _, want := range []string{
			"Services INFO", "0 failed units", "inspection 512/600 (unit inspection limit)",
			"Containers INFO", "docker", "0 running", "inspect: 64/100 (inspection limit)",
			"Devices INFO  1/8 device(s) checked (scan deadline)",
			"Deleted files INFO", "coverage 512/600 checked (process limit, permission)",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("%+v output missing %q:\n%s", options, want, text)
			}
		}
	}
}

func TestZeroSuccessDeviceHealthCoverageIsVisible(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{DeviceHealthCoverage: &model.DeviceHealthCoverage{
		DevicesEligible: 8, Limited: true, Reason: "SMART/NVMe tools unavailable",
	}}}
	var out strings.Builder
	Write(&out, report, Options{ASCII: true, Quiet: true})
	if got := out.String(); !strings.Contains(got, "Devices INFO  0/8 device(s) checked (SMART/NVMe tools unavailable)") {
		t.Fatalf("zero-success coverage was hidden:\n%s", got)
	}
}

func TestDeletedFilesReducedCoverageExplainsBelowThresholdObservationInDetails(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{DeletedFiles: &model.DeletedFiles{
		Available: true, TotalBytes: 996 << 10, UniqueFiles: 8,
		ProcessesScanned: 742, ProcessesSkipped: 4, ProcessesEligible: 746,
	}}}
	analyze.Report(&report)
	var out strings.Builder
	Write(&out, report, Options{ASCII: true, Verbose: true})
	text := out.String()
	for _, want := range []string{
		"Details", "Deleted-file scan has reduced coverage", "below the 200.0 MiB", "warning", "threshold.",
		"742/746 process(es) checked; 4 skipped due to permissions.",
		"Run glimpse with sudo for complete process visibility",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("details missing %q:\n%s", want, text)
		}
	}
}

func TestStorageLayerMountsDoNotInheritUnrelatedStorageInfo(t *testing.T) {
	report := model.Report{
		Metrics: model.Metrics{
			LVM: &model.LVM{PhysicalVolumes: []model.LVMPhysicalVolume{{}}, VolumeGroups: []model.LVMVolumeGroup{{}}, LogicalVolumes: []model.LVMLogicalVolume{{}}},
			MountChecks: []model.MountCheck{
				{MountPoint: "/", FSType: "ext4", Active: true, ActiveKnown: true},
				{MountPoint: "/boot", FSType: "ext4", Active: true, ActiveKnown: true},
			},
		},
		Findings: []model.Finding{{ID: "deleted-files-coverage", Severity: model.SeverityInfo, Category: "storage"}},
	}
	var out strings.Builder
	Write(&out, report, Options{ASCII: true, Verbose: true})
	text := out.String()
	for _, want := range []string{"Storage layers OK", "LVM OK", "Mounts OK  fstab mounts 2/2 active"} {
		if !strings.Contains(text, want) {
			t.Fatalf("storage layer status missing %q:\n%s", want, text)
		}
	}
}

func TestStorageLayersShowRestrictedLVMCoverageInNormalOutput(t *testing.T) {
	report := model.Report{
		Metrics:    model.Metrics{MountChecks: []model.MountCheck{{MountPoint: "/", FSType: "ext4", Active: true, ActiveKnown: true}}},
		Collection: []model.CollectionStatus{{Collector: "storage", Status: "info", Detail: "LVM metadata could not be read (pvs, vgs, lvs); this is usually restricted to root. Run with sudo to include LVM coverage."}},
	}
	var out strings.Builder
	Write(&out, report, Options{ASCII: true})
	if got := out.String(); !strings.Contains(got, "Storage layers INFO") || !strings.Contains(got, "LVM coverage requires sudo") || !strings.Contains(got, "LVM metadata INFO") || !strings.Contains(got, "Run with sudo to include LVM coverage.") {
		t.Fatalf("restricted LVM coverage was hidden or unexplained:\n%s", got)
	}
}
