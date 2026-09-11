package analyze

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

// TestSeverityAndScoreAgree guards the contract that broke silently: severity
// sets Score.Status, which cmd/glimpse turns into the process exit code, while
// ScoreImpact sets Score.Value. A Warning or Critical finding that subtracts
// nothing makes them disagree permanently -- the report reads 100/EXCELLENT
// and the exit code says otherwise. The rule is checked over the analyzer's
// real output rather than over a hand-written list, so a new rule is covered
// the moment it is added.
func TestSeverityAndScoreAgree(t *testing.T) {
	report := fullyPopulatedReport()
	Report(&report)
	if len(report.Findings) == 0 {
		t.Fatal("fixture produced no findings; the invariant would be vacuous")
	}
	if offenders := ActionableWithoutImpact(report.Findings); len(offenders) > 0 {
		t.Errorf("findings claim a severity that changes the exit code but subtract nothing: %v", offenders)
	}
}

// fullyPopulatedReport drives as many analyzer rules as one fixture
// reasonably can, so the invariants above are checked against real output
// rather than a hand-maintained list of findings.
func fullyPopulatedReport() model.Report {
	sampled := true
	tainted := true
	rebootRequired := true
	healthy := false
	passed := false
	unsynchronized := false
	offset := 9000.0
	failedAuth := uint64(500)
	denials := uint64(4)
	dumps := uint64(2)
	pidsMax := uint64(100)
	memMax := uint64(1 << 30)
	return model.Report{
		Host: model.Host{CPUCount: 2},
		Metrics: model.Metrics{
			CPU: &model.CPU{Sampled: &sampled, HostCPUCount: 2, Utilization: .97, Load1: 40, Steal: .4, IOWait: .5, Blocked: 4},
			Memory: &model.Memory{Sampled: &sampled, TotalBytes: 1 << 30, AvailableFraction: .01,
				SwapInBytes: 1 << 20, SwapOutBytes: 1 << 20, PageFaults: 500000, MajorFaults: 50000},
			Pressure: &model.Pressure{
				CPU:    model.PressureResource{SomeAvg10: 60},
				Memory: model.PressureResource{SomeAvg10: 40},
				IO:     model.PressureResource{SomeAvg10: 30},
			},
			Filesystems: []model.Filesystem{
				{MountPoint: "/", Type: "ext4", UsedFraction: .99, InodesTotal: 1000, InodesFree: 5},
				{MountPoint: "/mnt/warn", Type: "xfs", UsedFraction: .88},
				{MountPoint: "/mnt/ro", Type: "ext4", ReadOnly: true},
			},
			Network: []model.Network{{Name: "eth0", Sampled: &sampled, RXPackets: 1000, RXErrors: 500,
				RXDropped: 500, RXFIFOErrors: 500, TXPackets: 1000, TXErrors: 500, TXDropped: 500,
				TXFIFOErrors: 500, RXFrameErrors: 50, TXCarrierErrors: 50, Collisions: 50, Duplex: "full"}},
			Thermal:   []model.Thermal{{Name: "pkg", TemperatureC: 120, CriticalC: 100}},
			Processes: &model.Processes{Zombies: 3, StuckProcesses: []model.Process{{PID: 9, Command: "stuck"}}},
			Systemd: &model.Systemd{Available: true, FailedUnits: []string{"nginx.service"},
				RestartingUnits: []model.SystemdUnitRestart{{Unit: "api.service", RestartsDelta: 9}}},
			Kernel:    &model.Kernel{Available: true, Events: kernelEventsForEveryKind()},
			Disks:     []model.Disk{{Name: "sda", Sampled: &sampled, Utilization: .99, AverageQueueDepth: 9, AverageLatencyMillis: 500}},
			TCP:       &model.TCP{Sampled: &sampled, SegmentsOut: 10000, RetransmittedSegments: 5000, ListenOverflows: 10, ListenDrops: 10, ActiveOpens: 5000, AttemptFails: 4000, TimeWaitSockets: 999, OrphanSockets: 999},
			Conntrack: &model.Conntrack{Drops: 10, EarlyDrops: 10, InsertFailed: 10},
			DeviceHealth: []model.DeviceHealth{
				{Device: "sda", OverallPassed: &passed},
				{Device: "sdb", AvailableSpare: .01, PercentageUsed: .99},
			},
			TimeSync:  &model.TimeSync{Available: true, Service: "chrony", Synchronized: &unsynchronized, OffsetMillis: &offset},
			Resources: &model.Resources{OpenFiles: 999, OpenFilesMaximum: 1000, Processes: 999, ProcessesMaximum: 1000, ThreadsMaximum: 1000, Conntrack: 999, ConntrackMaximum: 1000, TimeWaitMaximum: 1000, OrphanMaximum: 1000, ListenBacklogMaximum: 128},
			CgroupV2: &model.CgroupV2{Available: true, MemoryOOMKillDelta: 2, MemoryOOMDelta: 2,
				CPUUsageSecondsDelta: 10, CPUThrottledSecondsDelta: 5, PIDsCurrent: 99, PIDsMax: &pidsMax,
				MemoryCurrentBytes: uint64(1<<30) - 1, MemoryMaxBytes: &memMax},
			Containers: []model.ContainerRuntime{{Runtime: "docker", Containers: []model.Container{{
				ID: "abc", Name: "web", OOMKilled: true, Healthy: &healthy, RestartCount: 9,
				State: "exited", HasRestartPolicy: true,
				LogEvents: []model.LogEvent{{Kind: model.LogKindPanic, Message: "panic: boom"}}}}}},
			ZFSPools: []model.ZFSPool{
				{Name: "tank", Health: "DEGRADED"},
				{Name: "spare", Health: "ONLINE", PermanentErrors: true},
				{Name: "ok", Health: "ONLINE", ReadErrors: 3, ScanState: "scrub in progress"},
			},
			SoftwareRAID: []model.SoftwareRAID{{Device: "md0", State: "degraded"}},
			LVM: &model.LVM{
				VolumeGroups:   []model.LVMVolumeGroup{{Name: "vg0", NeedsReview: true, ReviewReason: "not writable"}},
				LogicalVolumes: []model.LVMLogicalVolume{{Group: "vg0", Name: "lv0", NeedsReview: true, ReviewReason: "not active"}},
			},
			MountChecks: []model.MountCheck{{MountPoint: "/data", ActiveKnown: true}},
			Security: &model.Security{Available: true, RebootRequired: &rebootRequired, KernelTainted: &tainted,
				KernelTaintMask: 1, KernelTaintModules: []string{"proprietary"}, SELinux: "permissive",
				JournalWindow: "1h", FailedAuthAttempts: &failedAuth, SELinuxDenials: &denials,
				AppArmorDenials: &denials, CoreDumps: &dumps, CrashArtifacts: []string{"crash.1"},
				Vulnerabilities: []model.KernelVulnerability{{Name: "retbleed", Status: "Vulnerable: unmitigated"}}},
			NetworkState: &model.NetworkState{Available: true, RoutesAvailable: true,
				DNS: &model.DNSConfig{Available: true}},
			DNSResolution: &model.DNSResolution{Available: true,
				Local:    &model.DNSResolutionResult{Server: "127.0.0.53", Domain: "example.com"},
				External: &model.DNSResolutionResult{Server: "1.1.1.1", Domain: "example.com"}},
			GatewayCheck:   &model.GatewayCheck{Available: true, Gateway: "10.0.0.1", Sent: 3},
			DeletedFiles:   &model.DeletedFiles{Available: true, TotalBytes: 8 << 30, UniqueFiles: 3, ProcessesHolding: 2},
			PackageUpdates: &model.PackageUpdates{Available: true, Manager: "apt", Count: 12},
		},
		Collection: []model.CollectionStatus{{Collector: "cpu", Status: "ok"}},
	}
}

func kernelEventsForEveryKind() []model.LogEvent {
	events := make([]model.LogEvent, 0, len(model.KernelEventKinds))
	for _, kind := range model.KernelEventKinds {
		events = append(events, model.LogEvent{Kind: kind, Message: kind + " evidence"})
	}
	return events
}

// TestLabelNeverContradictsSeverity checks the other half: whatever the score,
// the label must not read more favourably than the highest severity present.
func TestLabelNeverContradictsSeverity(t *testing.T) {
	cases := []struct {
		score     int
		severity  model.Severity
		forbidden string
	}{
		{100, model.SeverityWarning, "EXCELLENT"},
		{95, model.SeverityWarning, "EXCELLENT"},
		{100, model.SeverityCritical, "EXCELLENT"},
		{100, model.SeverityCritical, "GOOD"},
	}
	for _, c := range cases {
		if got := label(c.score, c.severity); got == c.forbidden {
			t.Errorf("label(%d, %s) = %q, which contradicts the severity", c.score, c.severity, got)
		}
	}
	if got := label(100, model.SeverityOK); got != "EXCELLENT" {
		t.Errorf("a clean report should still read EXCELLENT, got %q", got)
	}
	if got := label(100, model.SeverityUnknown); got != "INSUFFICIENT DATA" {
		t.Errorf("label(100, unknown) = %q", got)
	}
}

// TestZeroImpactWarningWouldBeCaught proves the guard actually fires, so the
// test above cannot pass merely because the helper is broken.
func TestZeroImpactWarningWouldBeCaught(t *testing.T) {
	offenders := ActionableWithoutImpact([]model.Finding{
		{ID: "quiet-warning", Severity: model.SeverityWarning, ScoreImpact: 0},
		{ID: "info-finding", Severity: model.SeverityInfo, ScoreImpact: 0},
		{ID: "real-warning", Severity: model.SeverityWarning, ScoreImpact: 5},
	})
	if len(offenders) != 1 || offenders[0] != "quiet-warning" {
		t.Fatalf("guard did not identify the offending finding: %v", offenders)
	}
}

// TestEveryKernelEventKindIsHandled walks the vocabulary the kernel collector
// can emit and asserts the analyzer has a real answer for each. The analyzer
// previously matched "panic" and "oops" while the collector emitted
// kernel_panic and kernel_oops, so the two most severe events glimpse can
// detect fell through to the generic branch and were handed an unfiltered
// `journalctl -k | tail -50` that, after a panic reboot, contains nothing
// about the panic at all.
func TestEveryKernelEventKindIsHandled(t *testing.T) {
	const generic = "journalctl -k | tail -50"
	const genericSuggestion = "Inspect the kernel journal and affected hardware or workload."
	for _, kind := range model.KernelEventKinds {
		f := kernelFinding(model.LogEvent{Kind: kind, Message: kind + " evidence"}, nil)
		if f.DiagnosticCommand == generic {
			t.Errorf("%s: fell through to the unfiltered journal fallback", kind)
		}
		// link_up is the recovery half of a pair and has its own wording; every
		// other kind should say something specific to itself.
		if kind != model.KindLinkUp && f.Suggestion == genericSuggestion {
			t.Errorf("%s: fell through to the generic suggestion", kind)
		}
	}
}
