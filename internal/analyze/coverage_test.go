package analyze

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

// The following findings were implemented but had no test exercising them
// actually firing (found via an audit of internal/../ideas.md scenario
// coverage). Each test constructs the minimal report that should trigger the
// existing rule, so a future threshold or corroboration change that
// silently breaks one is caught.

func TestCPUContentionFiresWithCorroboratingSignals(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{
		CPU:      &model.CPU{Utilization: .95, Load1: 9},
		Pressure: &model.Pressure{CPU: model.PressureResource{SomeAvg10: 10}},
	}}
	Report(&report)
	if findingByID(report, "cpu-contention") == nil {
		t.Fatalf("expected cpu-contention to fire: %+v", report.Findings)
	}
}

func TestCgroupCPUThrottlingFiresOnSustainedRatio(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{
		CPU:      &model.CPU{},
		CgroupV2: &model.CgroupV2{Available: true, CPUUsageSecondsDelta: 1, CPUThrottledSecondsDelta: .2},
	}}
	Report(&report)
	if findingByID(report, "cgroup-cpu-throttling") == nil {
		t.Fatalf("expected cgroup-cpu-throttling to fire: %+v", report.Findings)
	}
}

func TestCgroupPIDLimitFiresNearCeiling(t *testing.T) {
	max := uint64(100)
	report := model.Report{Metrics: model.Metrics{
		CPU:      &model.CPU{},
		CgroupV2: &model.CgroupV2{Available: true, PIDsCurrent: 96, PIDsMax: &max},
	}}
	Report(&report)
	if findingByID(report, "cgroup-pids-limit") == nil {
		t.Fatalf("expected cgroup-pids-limit to fire: %+v", report.Findings)
	}
}

func TestMemoryPressureFiresWithSwapActivity(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{
		CPU:    &model.CPU{},
		Memory: &model.Memory{AvailableFraction: .05, SwapInBytes: 4096},
	}}
	Report(&report)
	if findingByID(report, "memory-pressure") == nil {
		t.Fatalf("expected memory-pressure to fire: %+v", report.Findings)
	}
}

func TestMemoryPressureFiresWithPSI(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{
		CPU:      &model.CPU{},
		Memory:   &model.Memory{AvailableFraction: .05},
		Pressure: &model.Pressure{Memory: model.PressureResource{SomeAvg10: 5}},
	}}
	Report(&report)
	if findingByID(report, "memory-pressure") == nil {
		t.Fatalf("expected memory-pressure to fire: %+v", report.Findings)
	}
}

func TestMemoryPressureDoesNotTreatUnknownAvailabilityAsZero(t *testing.T) {
	unknown := false
	report := model.Report{Metrics: model.Metrics{
		CPU:      &model.CPU{},
		Memory:   &model.Memory{AvailableValid: &unknown, AvailableFraction: 0, SwapInBytes: 4096},
		Pressure: &model.Pressure{Memory: model.PressureResource{SomeAvg10: 5}},
	}}
	Report(&report)
	if findingByID(report, "memory-pressure") != nil {
		t.Fatalf("unknown MemAvailable produced memory pressure: %+v", report.Findings)
	}
}

func TestMemoryPressureStillFiresForMeasuredZeroAvailability(t *testing.T) {
	valid := true
	report := model.Report{Metrics: model.Metrics{
		CPU:    &model.CPU{},
		Memory: &model.Memory{AvailableValid: &valid, AvailableFraction: 0, SwapInBytes: 4096},
	}}
	Report(&report)
	if findingByID(report, "memory-pressure") == nil {
		t.Fatalf("measured zero MemAvailable did not produce memory pressure: %+v", report.Findings)
	}
}

func TestResourceFileDescriptorsFiresNearCeiling(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{
		CPU:       &model.CPU{},
		Resources: &model.Resources{OpenFiles: 950, OpenFilesMaximum: 1000},
	}}
	Report(&report)
	found := findingByID(report, "resource-file-descriptors")
	if found == nil || found.Severity != model.SeverityWarning {
		t.Fatalf("expected a warning for file descriptors at 95%%: %+v", report.Findings)
	}

	report.Metrics.Resources.OpenFiles = 990
	Report(&report)
	found = findingByID(report, "resource-file-descriptors")
	if found == nil || found.Severity != model.SeverityCritical {
		t.Fatalf("expected critical for file descriptors at 99%%: %+v", report.Findings)
	}
}

func TestResourceTasksFiresNearCeiling(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{
		CPU:       &model.CPU{},
		Resources: &model.Resources{Processes: 96000, ThreadsMaximum: 100000, ProcessesMaximum: 4194304},
	}}
	Report(&report)
	if findingByID(report, "resource-tasks") == nil {
		t.Fatalf("expected resource-tasks to fire: %+v", report.Findings)
	}
}

func TestResourceConntrackFiresNearCeiling(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{
		CPU:       &model.CPU{},
		Resources: &model.Resources{Conntrack: 96000, ConntrackMaximum: 100000},
	}}
	Report(&report)
	if findingByID(report, "resource-conntrack") == nil {
		t.Fatalf("expected resource-conntrack to fire: %+v", report.Findings)
	}
}

func TestSecurityCoreDumpsFires(t *testing.T) {
	count := uint64(3)
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Security: &model.Security{CoreDumps: &count}}}
	Report(&report)
	if findingByID(report, "security-core-dumps") == nil {
		t.Fatalf("expected security-core-dumps to fire: %+v", report.Findings)
	}
}

func TestSecuritySELinuxAndAppArmorDenialsFire(t *testing.T) {
	selinux := uint64(2)
	apparmor := uint64(4)
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Security: &model.Security{SELinuxDenials: &selinux, AppArmorDenials: &apparmor}}}
	Report(&report)
	if findingByID(report, "security-selinux-denials") == nil {
		t.Fatalf("expected security-selinux-denials to fire: %+v", report.Findings)
	}
	if findingByID(report, "security-apparmor-denials") == nil {
		t.Fatalf("expected security-apparmor-denials to fire: %+v", report.Findings)
	}
}

func TestRaidResyncIsInformational(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, SoftwareRAID: []model.SoftwareRAID{
		{Device: "/dev/md0", State: "clean", ResyncProgress: "12.3% complete"},
	}}}
	Report(&report)
	found := findingByID(report, "raid-resync-/dev/md0")
	if found == nil || found.Severity != model.SeverityInfo {
		t.Fatalf("expected an informational rebuild finding: %+v", report.Findings)
	}
}

func TestTimeUnsynchronizedFires(t *testing.T) {
	synced := false
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, TimeSync: &model.TimeSync{Available: true, Service: "chrony", Synchronized: &synced}}}
	Report(&report)
	found := findingByID(report, "time-unsynchronized")
	if found == nil || found.Severity != model.SeverityWarning {
		t.Fatalf("expected time-unsynchronized to fire: %+v", report.Findings)
	}
}

func TestTimeOffsetWarnsThenCriticals(t *testing.T) {
	synced := true
	offset := 1500.0
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, TimeSync: &model.TimeSync{Available: true, Service: "chrony", Synchronized: &synced, OffsetMillis: &offset}}}
	Report(&report)
	found := findingByID(report, "time-offset")
	if found == nil || found.Severity != model.SeverityWarning {
		t.Fatalf("expected a warning for a 1.5s offset: %+v", report.Findings)
	}

	*report.Metrics.TimeSync.OffsetMillis = 6000
	Report(&report)
	found = findingByID(report, "time-offset")
	if found == nil || found.Severity != model.SeverityCritical {
		t.Fatalf("expected critical for a 6s offset: %+v", report.Findings)
	}
}

// A link coming back up is the recovery half of a link_down/link_up pair,
// not a fault; it must stay informational and cost nothing, even when it
// just happened (fresh enough that age-based step-down wouldn't apply).
func TestKernelLinkUpStaysInformational(t *testing.T) {
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Kernel: &model.Kernel{Available: true,
		Events: []model.LogEvent{{Kind: "link_up", Message: "enp7s0: NIC Link is Up 1000 Mbps"}}}}}
	Report(&report)
	found := findingByID(report, "kernel-link_up")
	if found == nil || found.Severity != model.SeverityInfo || found.ScoreImpact != 0 {
		t.Fatalf("expected link_up to stay informational with no score impact: %+v", report.Findings)
	}
}

// Each of these kernel-log pattern kinds is classified by the kernel
// collector already (see internal/collect/kernel); this pins the
// analyze-level severity every kind resolves to, not just the "oom" case.
func TestKernelEventKindsResolveExpectedSeverity(t *testing.T) {
	cases := map[string]model.Severity{
		"oom":                         model.SeverityCritical,
		"cgroup_oom":                  model.SeverityCritical,
		"kernel_panic":                model.SeverityCritical,
		"kernel_oops":                 model.SeverityCritical,
		"hardware_error":              model.SeverityCritical,
		"filesystem_corruption":       model.SeverityCritical,
		"filesystem_error":            model.SeverityWarning,
		"io_error":                    model.SeverityWarning,
		"nvme_error":                  model.SeverityWarning,
		"blocked_task":                model.SeverityWarning,
		"thermal_throttling":          model.SeverityWarning,
		"zfs_error":                   model.SeverityWarning,
		"filesystem_readonly_remount": model.SeverityCritical,
		"disk_full":                   model.SeverityCritical,
		"netdev_watchdog":             model.SeverityWarning,
		"segfault":                    model.SeverityWarning,
		"link_down":                   model.SeverityWarning,
	}
	for kind, want := range cases {
		report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Kernel: &model.Kernel{Available: true,
			Events: []model.LogEvent{{Kind: kind, Message: kind + " evidence"}}}}}
		Report(&report)
		found := findingByID(report, "kernel-"+kind)
		if found == nil {
			t.Fatalf("%s: expected a finding, got %+v", kind, report.Findings)
		}
		if found.Severity != want {
			t.Errorf("%s: severity = %s, want %s", kind, found.Severity, want)
		}
	}
}
