package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/model"
)

func TestReportMarksMissingCoreCoverageUnknown(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{Systemd: &model.Systemd{Available: false}}}
	Report(&report)
	if report.Score.Status != model.SeverityUnknown || report.Score.Label != "INSUFFICIENT DATA" || report.Score.Value != 0 {
		t.Fatalf("unexpected score: %#v", report.Score)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("collection coverage must not become a health finding: %#v", report.Findings)
	}
}

func TestDiskContentionRequiresCorrelatedSignals(t *testing.T) {
	report := model.Report{Host: model.Host{CPUCount: 4}, Metrics: model.Metrics{
		CPU:   &model.CPU{IOWait: .15},
		Disks: []model.Disk{{Name: "sda", Utilization: .95, AverageQueueDepth: 4, AverageLatencyMillis: 80}},
	}}
	Report(&report)
	if !hasFinding(report, "disk-contention-sda") {
		t.Fatalf("expected correlated disk finding: %#v", report.Findings)
	}
	report.Metrics.CPU.IOWait = 0
	Report(&report)
	if hasFinding(report, "disk-contention-sda") {
		t.Fatalf("throughput/saturation without host pressure must not warn: %#v", report.Findings)
	}
}

func TestDiskContentionEvidenceMatchesOnlyCorroboratingSignal(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{
		CPU:   &model.CPU{Blocked: 1},
		Disks: []model.Disk{{Name: "sda", Utilization: .90, AverageQueueDepth: 2, AverageLatencyMillis: 60}},
	}}
	Report(&report)
	for _, finding := range report.Findings {
		if finding.ID == "disk-contention-sda" && !contains(finding.Summary, "blocked tasks") {
			t.Fatalf("disk finding incorrectly described unavailable I/O pressure: %q", finding.Summary)
		}
	}
}

func TestTCPRetransmitUsesRatioAndVolume(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, TCP: &model.TCP{SegmentsOut: 10, RetransmittedSegments: 2}}}
	Report(&report)
	if hasFinding(report, "tcp-retransmits") {
		t.Fatalf("small TCP volume must not warn: %#v", report.Findings)
	}
	report.Metrics.TCP = &model.TCP{SegmentsOut: 500, RetransmittedSegments: 20}
	Report(&report)
	if !hasFinding(report, "tcp-retransmits") {
		t.Fatalf("expected high-volume retransmit finding: %#v", report.Findings)
	}
}

// Elevated TCP retransmissions is a system-wide counter: an application
// racing connections over broken IPv6 before falling back to IPv4 (or never
// falling back at all) contributes its unanswered SYN retries to the exact
// same counter as a genuinely lossy path. When the IPv6 check independently
// reports the host as unreachable, the retransmit finding should point at
// that as the likely cause instead of reading as a second, unrelated fault.
func TestTCPRetransmitCorrelatesWithBrokenIPv6(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{
		CPU:       &model.CPU{},
		TCP:       &model.TCP{SegmentsOut: 500, RetransmittedSegments: 20},
		IPv6Check: &model.IPv6Check{Available: true, Target: "2606:4700:4700::1111", Sent: 3, Received: 0},
	}}
	Report(&report)
	found := findingByID(report, "tcp-retransmits")
	if found == nil {
		t.Fatalf("expected the retransmit finding: %#v", report.Findings)
	}
	if !contains(found.Summary, "IPv6 reachability check also failed") {
		t.Fatalf("retransmit finding did not mention the correlated IPv6 failure: %+v", found)
	}
	if !contains(found.Suggestion, "Fix or disable IPv6 first") {
		t.Fatalf("retransmit suggestion did not point at IPv6 first: %+v", found)
	}
}

// A working IPv6 check (or none at all) must not add the IPv6 caveat -- it
// would be actively misleading on a host where IPv6 is not the cause.
func TestTCPRetransmitStaysUncorrelatedWhenIPv6Works(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{
		CPU:       &model.CPU{},
		TCP:       &model.TCP{SegmentsOut: 500, RetransmittedSegments: 20},
		IPv6Check: &model.IPv6Check{Available: true, Target: "2606:4700:4700::1111", Sent: 3, Received: 3},
	}}
	Report(&report)
	found := findingByID(report, "tcp-retransmits")
	if found == nil {
		t.Fatalf("expected the retransmit finding: %#v", report.Findings)
	}
	if contains(found.Summary, "IPv6") {
		t.Fatalf("healthy IPv6 must not be blamed: %+v", found)
	}
}

func TestDeviceMediaErrorsAreCritical(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, DeviceHealth: []model.DeviceHealth{{Device: "nvme0n1", Kind: "nvme", MediaErrors: 1}}}}
	Report(&report)
	for _, finding := range report.Findings {
		if finding.ID == "device-health-nvme0n1" && finding.Severity == model.SeverityCritical {
			return
		}
	}
	t.Fatalf("expected critical device health finding: %#v", report.Findings)
}

func TestCgroupFindingsUseSampledEvents(t *testing.T) {
	max := uint64(100)
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, CgroupV2: &model.CgroupV2{
		Available:          true,
		Containerized:      true,
		MemoryCurrentBytes: 99,
		MemoryMaxBytes:     &max,
	}}}
	Report(&report)
	if hasFinding(report, "cgroup-memory-limit") || hasFinding(report, "cgroup-oom-kill") {
		t.Fatalf("a nearly full cgroup without pressure or sampled OOM must not warn: %#v", report.Findings)
	}
	report.Metrics.CgroupV2.MemoryOOMKillDelta = 1
	Report(&report)
	if !hasFinding(report, "cgroup-oom-kill") || !hasFinding(report, "cgroup-memory-limit") {
		t.Fatalf("expected corroborated cgroup findings: %#v", report.Findings)
	}
}

func TestCgroupMemoryLimitDoesNotRequireRuntimeClassification(t *testing.T) {
	max := uint64(100)
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, CgroupV2: &model.CgroupV2{
		Available:          true,
		Containerized:      false,
		MemoryCurrentBytes: 99,
		MemoryMaxBytes:     &max,
		MemoryOOMDelta:     1,
	}}}
	Report(&report)
	if !hasFinding(report, "cgroup-memory-limit") {
		t.Fatalf("finite pressured cgroup limit must be reported regardless of runtime classification: %#v", report.Findings)
	}
}

func TestContainerRestartDeltaAndHealth(t *testing.T) {
	healthy := true
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Containers: []model.ContainerRuntime{{Runtime: "podman", Containers: []model.Container{{Name: "web", State: "running", Healthy: &healthy}}}}}}
	Report(&report)
	if len(report.Findings) != 0 {
		t.Fatalf("healthy container must not create a finding: %#v", report.Findings)
	}
	unhealthy := false
	report.Metrics.Containers[0].Containers[0].Healthy = &unhealthy
	report.Metrics.Containers[0].Containers[0].RestartCount = 3
	Report(&report)
	if !hasFinding(report, "container-podman-web-unhealthy") || !hasFinding(report, "container-podman-web-restarts") {
		t.Fatalf("expected unhealthy/restarting findings: %#v", report.Findings)
	}
	if found := findingByID(report, "container-podman-web-restarts"); found == nil || found.Severity != model.SeverityCritical {
		t.Fatalf("three restarts must be critical: %#v", report.Findings)
	}
}

func TestContainerLogEventsAreActionableButNotCriticalAlone(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Containers: []model.ContainerRuntime{{Runtime: "podman", Containers: []model.Container{{Name: "web", State: "running", LogEvents: []model.LogEvent{{Kind: "panic", Message: "panic: boom"}}}}}}}}
	Report(&report)
	for _, finding := range report.Findings {
		if finding.ID == "container-podman-web-log-events" {
			if finding.Severity != model.SeverityWarning || finding.Title == "" || !contains(finding.Summary, "web") || !contains(finding.Suggestion, "podman logs --since 1h web") || contains(finding.Suggestion, "fix the reported") {
				t.Fatalf("unexpected finding: %#v", finding)
			}
			return
		}
	}
	t.Fatalf("expected container log finding: %#v", report.Findings)
}

func TestZombieFindingNamesProcessAndParent(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Processes: &model.Processes{Zombies: 1, ZombieProcesses: []model.Process{{PID: 81, ParentPID: 12, Command: "worker", ParentCommand: "supervisor", State: "Z"}}}}}
	Report(&report)
	for _, finding := range report.Findings {
		if finding.ID == "zombies" {
			if !contains(finding.Summary, "PID 81 (worker), parent PID 12 (supervisor)") || !contains(finding.Suggestion, "ps -fp 12") {
				t.Fatalf("finding does not identify zombie/parent: %#v", finding)
			}
			return
		}
	}
	t.Fatalf("expected zombie finding: %#v", report.Findings)
}

func TestStuckProcessFindingNamesProcessAndParent(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Processes: &model.Processes{StuckProcesses: []model.Process{{PID: 91, ParentPID: 12, Command: "tail", State: "D"}}}}}
	Report(&report)
	found := findingByID(report, "process-stuck-uninterruptible")
	if found == nil || !contains(found.Summary, "PID 91 (tail), parent PID 12") || found.Severity != model.SeverityWarning {
		t.Fatalf("expected a warning naming the stuck process: %#v", report.Findings)
	}
}

func TestStuckProcessFindingEscalatesWithMultipleProcesses(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Processes: &model.Processes{StuckProcesses: []model.Process{
		{PID: 1, Command: "a", State: "D"}, {PID: 2, Command: "b", State: "D"}, {PID: 3, Command: "c", State: "D"},
	}}}}
	Report(&report)
	found := findingByID(report, "process-stuck-uninterruptible")
	if found == nil || found.Severity != model.SeverityCritical {
		t.Fatalf("expected critical severity for 3+ stuck processes: %#v", report.Findings)
	}
}

func TestNoStuckProcessesProducesNoFinding(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Processes: &model.Processes{Blocked: 1}}}
	Report(&report)
	if hasFinding(report, "process-stuck-uninterruptible") {
		t.Fatalf("a momentary blocked count without an identified stuck process must not fire: %#v", report.Findings)
	}
}

func TestPackageManagerRebootFindingIsRecommended(t *testing.T) {
	required := true
	report := model.Report{Metrics: model.Metrics{Security: &model.Security{RebootRequired: &required, RebootFromPackages: true}}}
	findings := AnalyzeSecurity(&report)
	if len(findings) != 1 || findings[0].Title != "recommended Reboot is pending" {
		t.Fatalf("unexpected reboot finding: %+v", findings)
	}
}

func TestSquashfsReadOnlyMountsAreQuiet(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{Filesystems: []model.Filesystem{{MountPoint: "/snap/core", Type: "squashfs", ReadOnly: true}}}}
	Report(&report)
	for _, finding := range report.Findings {
		if strings.HasPrefix(finding.ID, "filesystem-read-only-") {
			t.Fatalf("squashfs read-only mount became a finding: %+v", finding)
		}
	}
}

func TestZFSOnlinePoolWithNoErrorsIsQuiet(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, ZFSPools: []model.ZFSPool{{Name: "tank", Health: "ONLINE"}}}}
	Report(&report)
	if len(report.Findings) != 0 {
		t.Fatalf("online clean pool must not create a finding: %#v", report.Findings)
	}
	report.Metrics.ZFSPools[0].Health = "DEGRADED"
	Report(&report)
	if !hasFinding(report, "zfs-pool-tank-health") {
		t.Fatalf("expected degraded-pool finding: %#v", report.Findings)
	}
}

func hasFinding(report model.Report, id string) bool {
	for _, finding := range report.Findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func contains(text, substring string) bool {
	for i := 0; i+len(substring) <= len(text); i++ {
		if text[i:i+len(substring)] == substring {
			return true
		}
	}
	return false
}

func TestSelectedSectionsRetainFindings(t *testing.T) {
	cases := []struct {
		name    string
		metrics model.Metrics
		id      string
	}{
		{"services", model.Metrics{Systemd: &model.Systemd{Available: true, FailedUnits: []string{"database.service"}}}, "failed-units"},
		{"network", model.Metrics{TCP: &model.TCP{SegmentsOut: 1000, RetransmittedSegments: 100}}, "tcp-retransmits"},
		{"zfs", model.Metrics{ZFSPools: []model.ZFSPool{{Name: "tank", Health: "DEGRADED"}}}, "zfs-pool-tank-health"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := model.Report{Metrics: tt.metrics}
			Report(&r)
			if !hasFinding(r, tt.id) {
				t.Fatalf("missing finding: %+v", r)
			}
		})
	}
}

func TestFilesystemInodesAndIntentionalReadOnly(t *testing.T) {
	r := model.Report{Metrics: model.Metrics{Filesystems: []model.Filesystem{{MountPoint: "/data", UsedFraction: .2, InodesTotal: 1000, InodesFree: 0}}}}
	Report(&r)
	if !hasFinding(r, "filesystem-inodes-/data") || r.Score.Status != model.SeverityCritical {
		t.Fatalf("inode exhaustion missed: %+v", r)
	}
	r.Metrics.Filesystems[0].ReadOnly = true
	Report(&r)
	if r.Score.Status != model.SeverityInfo || r.Score.Value != 100 {
		t.Fatalf("intentional read-only mount penalized: %+v", r)
	}
}

func TestNetworkRequiresVolumeAndRatio(t *testing.T) {
	for _, tt := range []struct {
		packets, drops uint64
		warn           bool
	}{{1000000, 1, false}, {1000000, 10, false}, {1000, 100, true}, {0, 20, true}} {
		r := model.Report{Metrics: model.Metrics{Network: []model.Network{{Name: "eth0", RXPackets: tt.packets, RXDropped: tt.drops}}}}
		Report(&r)
		if got := r.Score.Status == model.SeverityWarning; got != tt.warn {
			t.Fatalf("%+v -> %+v", tt, r.Score)
		}
	}
}

func TestSuccessfulEmptySectionIsHealthy(t *testing.T) {
	r := model.Report{Metrics: model.Metrics{Systemd: &model.Systemd{Available: true}}}
	Report(&r)
	if r.Score.Status != model.SeverityOK {
		t.Fatalf("empty successful result: %+v", r.Score)
	}
}

func TestOptionalSuccessDoesNotHideMissingCoreCoverage(t *testing.T) {
	r := model.Report{Metrics: model.Metrics{Systemd: &model.Systemd{Available: true}}, Collection: []model.CollectionStatus{{Collector: "cpu", Status: "error"}}}
	Report(&r)
	if r.Score.Status != model.SeverityUnknown {
		t.Fatalf("missing core facts treated as healthy: %+v", r.Score)
	}
	r.Metrics.Systemd.FailedUnits = []string{"database.service"}
	Report(&r)
	if !hasFinding(r, "failed-units") || r.Score.Status != model.SeverityUnknown {
		t.Fatalf("incomplete coverage must retain evidence but invalidate the verdict: %+v", r)
	}
}

func TestFailedSystemdUnitsIncludeStateChangeTime(t *testing.T) {
	since := time.Date(2026, 9, 8, 10, 43, 2, 0, time.Local)
	report := model.Report{Metrics: model.Metrics{Systemd: &model.Systemd{
		Available: true, FailedUnits: []string{"glimpse-test-failure.service"},
		FailedUnitSince: map[string]time.Time{"glimpse-test-failure.service": since},
	}}}
	Report(&report)
	found := findingByID(report, "failed-units")
	if found == nil || !strings.Contains(found.Summary, "glimpse-test-failure.service (since 10:43 2026-09-08)") {
		t.Fatalf("failed-unit summary missing time: %+v", found)
	}
}

func TestReportIncludesSecurityAndActiveZFSScan(t *testing.T) {
	pending := true
	report := model.Report{Metrics: model.Metrics{
		Security: &model.Security{Available: true, RebootRequired: &pending},
		ZFSPools: []model.ZFSPool{{Name: "tank", Health: "ONLINE", ScanState: "scrub in progress since today"}},
	}}
	Report(&report)
	if report.Score.Value != 100 {
		t.Fatalf("informational checks changed score: %+v", report.Score)
	}
	ids := map[string]bool{}
	for _, f := range report.Findings {
		ids[f.ID] = true
	}
	if !ids["security-reboot-required"] || !ids["zfs-pool-tank-scan"] {
		t.Fatalf("missing findings: %+v", report.Findings)
	}
}

func TestStealRequiresCorroboratingPressure(t *testing.T) {
	for _, pressure := range []float64{0, 6} {
		report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{Steal: .2}, Pressure: &model.Pressure{CPU: model.PressureResource{SomeAvg10: pressure}}}}
		Report(&report)
		found := false
		for _, f := range report.Findings {
			if f.ID == "cpu-steal" {
				found = true
			}
		}
		if found != (pressure >= 5) {
			t.Fatalf("pressure %v: %+v", pressure, report.Findings)
		}
	}
}
