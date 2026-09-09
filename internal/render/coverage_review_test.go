package render

import (
	"strings"
	"testing"

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
