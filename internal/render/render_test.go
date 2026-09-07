package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/model"
)

func TestWriteIncludesMilestoneTwoSummaries(t *testing.T) {
	synchronized := true
	report := model.Report{
		Host:                  model.Host{Hostname: "host", CPUCount: 2},
		Score:                 model.Score{Value: 100, Status: model.SeverityOK, Label: "EXCELLENT"},
		SampleDurationSeconds: 5,
		Metrics: model.Metrics{
			Disks:     []model.Disk{{Name: "sda", Utilization: .6, ReadBytes: 5 * 1024 * 1024}},
			TCP:       &model.TCP{SegmentsOut: 100, RetransmittedSegments: 3, ListenDrops: 1},
			TimeSync:  &model.TimeSync{Available: true, Service: "chrony", Synchronized: &synchronized},
			Resources: &model.Resources{OpenFiles: 9, OpenFilesMaximum: 10},
		},
	}
	var output bytes.Buffer
	Write(&output, report, Options{})
	for _, want := range []string{"Disk OK  1 physical disk", "TCP OK  3 retransmits", "Time OK  chrony synchronized", "Limits OK  FDs 9/10"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("rendered report missing %q:\n%s", want, output.String())
		}
	}
}

func TestWriteWrapsNarrowASCIIOutput(t *testing.T) {
	report := model.Report{
		Host:  model.Host{Hostname: "example-host", OS: "Linux", CPUCount: 2},
		Score: model.Score{Value: 88, Status: model.SeverityWarning, Label: "GOOD"},
		Findings: []model.Finding{{
			Severity: model.SeverityWarning,
			Title:    "A deliberately long finding title",
			Summary:  "This summary must wrap cleanly at a narrow terminal width without Unicode rendering artifacts.",
		}},
	}
	var output bytes.Buffer
	Write(&output, report, Options{Width: 40, ASCII: true})
	for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		if len(line) > 40 {
			t.Fatalf("line wider than 40 columns: %q", line)
		}
	}
	if strings.ContainsAny(output.String(), "·▁▂▃▄▅▆▇█°") {
		t.Fatalf("ASCII output contains Unicode decoration:\n%s", output.String())
	}
}

func TestWriteSanitizesExternalTextAndRendersBoundedDetails(t *testing.T) {
	report := model.Report{
		Host:  model.Host{Hostname: "host\x1b[31m-evil", OS: "Linux\nInjected", Kernel: "6.8"},
		Score: model.Score{Value: 60, Status: model.SeverityWarning, Label: "CHECK"},
		Metrics: model.Metrics{Processes: &model.Processes{TopCPU: []model.Process{
			{PID: 42, Command: "worker\x1b[2J", RSSBytes: 2 * 1024 * 1024},
			{PID: 43, Command: "second"}, {PID: 44, Command: "third"}, {PID: 45, Command: "fourth"},
		}}},
		Findings: []model.Finding{{Severity: model.SeverityWarning, Title: "bad\x1b[31mtitle", Summary: "summary\nline", Evidence: []model.Evidence{
			{Label: "one", Value: "value"}, {Label: "two", Value: "value"}, {Label: "three", Value: "value"}, {Label: "four", Value: "value"},
		}}},
	}
	var output bytes.Buffer
	Write(&output, report, Options{Color: true, Verbose: true, Width: 60})
	text := output.String()
	if strings.Contains(text, "\x1b[31m-evil") || strings.Contains(text, "Linux\nInjected") || strings.Contains(text, "bad\x1b[31mtitle") || strings.Contains(text, "worker\x1b[2J") {
		t.Fatalf("external escape/control text was not sanitized:\n%s", text)
	}
	if !strings.Contains(text, "(1 more evidence items)") || !strings.Contains(text, "(1 more processes)") {
		t.Fatalf("bounded detail omission was not indicated:\n%s", text)
	}
}

func TestOverviewAndDetailsHeadersAreColoredAndSeparated(t *testing.T) {
	var output bytes.Buffer
	Write(&output, model.Report{
		Metrics:  model.Metrics{CPU: &model.CPU{}},
		Findings: []model.Finding{{Severity: model.SeverityWarning, Title: "Example finding"}},
	}, Options{Color: true})
	text := output.String()
	for _, header := range []string{"\x1b[35mOverview\x1b[0m", "\x1b[35mDetails\x1b[0m"} {
		if !strings.Contains(text, header) {
			t.Fatalf("missing colored header %q:\n%s", header, text)
		}
	}
	if !strings.Contains(text, "\n\n\x1b[35mOverview\x1b[0m\n") || !strings.Contains(text, "\n\n\x1b[35mDetails\x1b[0m\n") {
		t.Fatalf("section headers must have a free line above them:\n%s", text)
	}
}

func TestInfoOnlyDetailsHaveAHeaderWithoutSeparatingLimits(t *testing.T) {
	var output bytes.Buffer
	Write(&output, model.Report{
		Metrics: model.Metrics{
			CPU:        &model.CPU{},
			Resources:  &model.Resources{OpenFiles: 1, OpenFilesMaximum: 2},
			Containers: []model.ContainerRuntime{{Runtime: "docker"}},
		},
		Findings: []model.Finding{{Severity: model.SeverityInfo, Title: "Informational fact"}},
	}, Options{ASCII: true})
	text := output.String()
	limits := strings.Index(text, "Limits OK")
	containers := strings.Index(text, "Containers OK")
	if limits < 0 || containers < 0 || strings.Contains(text[limits:containers], "\n\n") {
		t.Fatalf("overview must flow directly into integrations:\n%s", text)
	}
	if !strings.Contains(text, "\n\nDetails\nINFO  Informational fact") {
		t.Fatalf("INFO-only details must retain their heading:\n%s", text)
	}
}

func TestWriteColoredNarrowOutputFitsDisplayWidth(t *testing.T) {
	report := model.Report{
		Host:  model.Host{Hostname: "host", OS: "Linux"},
		Score: model.Score{Value: 80, Status: model.SeverityOK, Label: "GOOD"},
	}
	var output bytes.Buffer
	Write(&output, report, Options{Color: true, Width: 60})
	for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		if displayWidth(line) > 60 {
			t.Fatalf("line wider than 60 display cells: %q (width %d)", line, displayWidth(line))
		}
	}
}

func TestWriteWrappedPreservesTrustedIndent(t *testing.T) {
	var output bytes.Buffer
	writeWrapped(&output, 20, "    ", "one two three four")
	for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		if !strings.HasPrefix(line, "    ") {
			t.Fatalf("wrapped line lost indentation: %q", line)
		}
	}
}

func TestSafeTextRemovesFormatControls(t *testing.T) {
	got := SafeText("left\u202Eright\x1b[31m")
	if strings.ContainsAny(got, "\x1b\u202E") {
		t.Fatalf("unsafe control survived: %q", got)
	}
}

func TestWriteUsesMetricSampleDurationsForRates(t *testing.T) {
	report := model.Report{
		Host:                  model.Host{Hostname: "host"},
		Score:                 model.Score{Value: 100, Status: model.SeverityOK, Label: "GOOD"},
		SampleDurationSeconds: 120,
		Metrics: model.Metrics{
			Disks:   []model.Disk{{Name: "sda", ReadBytes: 60 * 1024 * 1024, SampleDurationSeconds: 60}},
			Network: []model.Network{{Name: "eth0", RXBytes: 60 * 1024 * 1024, SampleDurationSeconds: 60}},
		},
	}
	var output bytes.Buffer
	Write(&output, report, Options{ASCII: true})
	text := output.String()
	if !strings.Contains(text, "Disk OK  1 physical disk | sda 0% busy | 1.0 MiB/s") {
		t.Fatalf("disk rate did not use metric duration:\n%s", text)
	}
	if !strings.Contains(text, "Network OK  1 interfaces | eth0 RX 1.0 MiB/s") {
		t.Fatalf("network rate did not use metric duration:\n%s", text)
	}
}

func TestUnsampledCPUDoesNotRenderAsIdle(t *testing.T) {
	sampled := false
	var output bytes.Buffer
	Write(&output, model.Report{Metrics: model.Metrics{CPU: &model.CPU{Sampled: &sampled, Load1: 2}}}, Options{})
	if !strings.Contains(output.String(), "utilization unavailable") || strings.Contains(output.String(), "0% avg") {
		t.Fatalf("unsampled CPU rendered as idle: %s", output.String())
	}
}

func TestProcessThermalAndIntegrationLabels(t *testing.T) {
	var output bytes.Buffer
	Write(&output, model.Report{Metrics: model.Metrics{
		Thermal:    []model.Thermal{{Name: "coretemp: Package id 0", TemperatureC: 42.6}},
		Processes:  &model.Processes{TopCPU: []model.Process{{Command: "python3", PID: 42, CPUFraction: 1.25, RSSBytes: 50 * 1024 * 1024}}},
		Containers: []model.ContainerRuntime{{Runtime: "docker", Containers: []model.Container{{State: "running"}}}},
		ZFSPools:   []model.ZFSPool{{Name: "tank", Health: "ONLINE", ScanState: "scrub repaired 0B with 0 errors"}},
	}}, Options{Verbose: true, Width: 120})
	for _, want := range []string{"maximum reported temperature (CPU sensor)", "CPU 125.0%", "RAM 50.0 MiB", "resident/RSS", "docker", "tank", "ONLINE"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %q: %s", want, output.String())
		}
	}
}

func TestWriteOmitsTrendAndHealthyDeviceHealthNoise(t *testing.T) {
	var output bytes.Buffer
	Write(&output, model.Report{Metrics: model.Metrics{
		DeviceHealth: []model.DeviceHealth{{Device: "sda"}},
		Trends:       []model.Trend{{Name: "cpu.utilization", Values: []float64{.1, .9}}},
	}}, Options{})
	if strings.Contains(output.String(), "Trends") || strings.Contains(output.String(), "device health reports") {
		t.Fatal(output.String())
	}
}

func TestContainerSummaryExplainsBoundedLogCheck(t *testing.T) {
	var output bytes.Buffer
	Write(&output, model.Report{Metrics: model.Metrics{Containers: []model.ContainerRuntime{{
		Runtime: "docker", Containers: []model.Container{{State: "running"}}, LogsChecked: 1, LogCandidates: 2, LogCheckLimited: true,
	}}}}, Options{})
	if !strings.Contains(output.String(), "Containers OK  docker") || !strings.Contains(output.String(), "logs: 1/2 checked (time limit)") {
		t.Fatal(output.String())
	}
}

func TestContainerSummaryDoesNotElevateGenericLogIssuesWithoutFinding(t *testing.T) {
	var output bytes.Buffer
	Write(&output, model.Report{Metrics: model.Metrics{Containers: []model.ContainerRuntime{{
		Runtime: "docker", Containers: []model.Container{{State: "running", LogEvents: []model.LogEvent{{Kind: "error", Message: "error"}}}}, LogsChecked: 1, LogCandidates: 1,
	}}}}, Options{})
	if !strings.Contains(output.String(), "Containers OK  docker") || !strings.Contains(output.String(), "1 log issue") {
		t.Fatal(output.String())
	}
}

// These cases exercise the analyzer and the renderer together. A section's
// visible badge must reflect the analyzer-owned finding severity; rendering
// must not silently add or downgrade health policy of its own.
func TestIntegrationSectionSeverityMatchesAnalyzerFindings(t *testing.T) {
	tests := []struct {
		name   string
		report model.Report
		want   string
	}{
		{
			name: "generic container wording remains informational",
			report: model.Report{Metrics: model.Metrics{Containers: []model.ContainerRuntime{{
				Runtime:    "podman",
				Containers: []model.Container{{Name: "web", State: "running", LogEvents: []model.LogEvent{{Kind: "error", Message: "retry error"}}}},
			}}}},
			want: "Containers INFO",
		},
		{
			name: "intentional exited container remains okay",
			report: model.Report{Metrics: model.Metrics{Containers: []model.ContainerRuntime{{
				Runtime: "podman", Containers: []model.Container{{Name: "job", State: "exited"}},
			}}}},
			want: "Containers OK",
		},
		{
			name: "critical kernel event stays critical",
			report: model.Report{Metrics: model.Metrics{Kernel: &model.Kernel{
				Available: true, Events: []model.LogEvent{{Kind: "kernel_panic", Message: "panic"}},
			}}},
			want: "Kernel CRIT",
		},
		{
			name: "selinux permissive stays warning",
			report: model.Report{Metrics: model.Metrics{Security: &model.Security{
				Available: true, SELinux: "permissive", AppArmor: "enabled",
			}}},
			want: "Security WARN",
		},
		{
			name: "cgroup oom stays critical",
			report: model.Report{Metrics: model.Metrics{CgroupV2: &model.CgroupV2{
				Available: true, Containerized: true, MemoryOOMKillDelta: 1,
			}}},
			want: "Cgroup v2 CRIT",
		},
		{
			name: "device endurance warning stays warning",
			report: model.Report{Metrics: model.Metrics{DeviceHealth: []model.DeviceHealth{{
				Device: "nvme0n1", Kind: "nvme", AvailableSpare: .04, PercentageUsed: .96,
			}}}},
			want: "Devices WARN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyze.Report(&tt.report)
			var output bytes.Buffer
			Write(&output, tt.report, Options{ASCII: true})
			if !strings.Contains(output.String(), tt.want) {
				t.Fatalf("rendered report missing %q:\n%s\nfindings: %#v", tt.want, output.String(), tt.report.Findings)
			}
		})
	}
}

func TestSecurityKernelTaintExplainsInfoInline(t *testing.T) {
	var output bytes.Buffer
	Write(&output, model.Report{Metrics: model.Metrics{Security: &model.Security{
		Available: true, SELinux: "unknown", AppArmor: "enabled", KernelTaintMask: 4097, KernelTaintModules: []string{"zfs", "spl"},
	}}, Findings: []model.Finding{{ID: "security-kernel-tainted", Severity: model.SeverityInfo, Category: "security"}}}, Options{ASCII: true})
	if got := output.String(); !strings.Contains(got, "Security INFO") || !strings.Contains(got, "Kernel taint INFO  mask 4097 (modules zfs,spl)") {
		t.Fatalf("security INFO lacks inline taint evidence:\n%s", got)
	}
}

func TestContainerLogDetailsAreCompactAndColorCommand(t *testing.T) {
	var output bytes.Buffer
	Write(&output, model.Report{Metrics: model.Metrics{Containers: []model.ContainerRuntime{{
		Runtime: "docker", Containers: []model.Container{{Name: "samba", State: "running", LogEvents: []model.LogEvent{{Kind: "error", Message: "foo error"}}}},
	}}}, Findings: []model.Finding{{Severity: model.SeverityWarning, Category: "containers", Title: "samba", Evidence: []model.Evidence{{Value: "foo error"}}, Suggestion: "Review with docker logs --since 1h samba"}}}, Options{Color: true})
	text := output.String()
	if !strings.Contains(text, "foo error") || strings.Contains(text, "error: foo error") || strings.Contains(text, "and fix") || !strings.Contains(text, "docker logs --since 1h samba") {
		t.Fatalf("container log details were rendered incorrectly: %s", text)
	}
	if !strings.Contains(text, "\x1b[33mWARN\x1b[0m  \x1b[1;33msamba\x1b[0m") || !strings.Contains(text, "    foo error") || strings.Contains(text, "error: foo error") || !strings.Contains(text, "and fix") || !strings.Contains(text, "\x1b[34mdocker logs --since 1h samba\x1b[0m") || !strings.Contains(text, "\x1b[35mDetails\x1b[0m") {
		t.Log(text)
	}
}

func TestSectionStatusesUseConsistentSeverityColors(t *testing.T) {
	var output bytes.Buffer
	Write(&output, model.Report{
		Metrics:  model.Metrics{CPU: &model.CPU{}, Memory: &model.Memory{}},
		Findings: []model.Finding{{Category: "memory", Severity: model.SeverityWarning}},
	}, Options{Color: true})
	text := output.String()
	if !strings.Contains(text, "\x1b[32mOK\x1b[0m") || !strings.Contains(text, "\x1b[33mWARN\x1b[0m") {
		t.Fatal(text)
	}
}

func TestUnsampledProcessCPUIsExplicit(t *testing.T) {
	unavailable := false
	var output bytes.Buffer
	Write(&output, model.Report{Metrics: model.Metrics{Processes: &model.Processes{TopCPU: []model.Process{{Command: "new-worker", CPUSampled: &unavailable}}}}}, Options{Verbose: true})
	if !strings.Contains(output.String(), "CPU unavailable") || strings.Contains(output.String(), "CPU 0.0%") {
		t.Fatal(output.String())
	}
}

func TestProcessesAreVerboseUnlessActionable(t *testing.T) {
	var output bytes.Buffer
	Write(&output, model.Report{Metrics: model.Metrics{Processes: &model.Processes{TopCPU: []model.Process{{Command: "worker"}}}}}, Options{})
	if strings.Contains(output.String(), "Top CPU") {
		t.Fatal(output.String())
	}
}

// A CPU (or memory) finding names no culprit by itself; Top CPU/RAM must
// surface in the default report so the reader does not have to reach for
// --verbose just to see which process is responsible.
func TestTopCPUShownOnCPUFindingWithoutVerbose(t *testing.T) {
	report := model.Report{
		Metrics:  model.Metrics{Processes: &model.Processes{TopCPU: []model.Process{{Command: "yes", PID: 123}}}},
		Findings: []model.Finding{{ID: "cpu-contention", Severity: model.SeverityWarning, Category: "cpu", Title: "Sustained CPU contention"}},
	}
	var output bytes.Buffer
	Write(&output, report, Options{})
	if !strings.Contains(output.String(), "Top CPU") || !strings.Contains(output.String(), "yes") {
		t.Fatal(output.String())
	}
}

func TestTopRAMShownOnMemoryFindingWithoutVerbose(t *testing.T) {
	report := model.Report{
		Metrics:  model.Metrics{Processes: &model.Processes{TopRSS: []model.Process{{Command: "leaky", PID: 456}}}},
		Findings: []model.Finding{{ID: "memory-pressure", Severity: model.SeverityWarning, Category: "memory", Title: "Memory pressure observed"}},
	}
	var output bytes.Buffer
	Write(&output, report, Options{})
	if !strings.Contains(output.String(), "Top RAM") || !strings.Contains(output.String(), "leaky") {
		t.Fatal(output.String())
	}
}

func TestFormatSuggestionColorsPrefixAndCommand(t *testing.T) {
	got := formatSuggestion("Review with docker logs --since 1h samba", true)
	want := "\x1b[37mReview with \x1b[0m\x1b[34mdocker logs --since 1h samba\x1b[0m"
	if got != want {
		t.Fatalf("formatSuggestion() = %q, want %q", got, want)
	}
}

// Rendering every value in MiB is fine for a process's resident set but
// produces "23068672.0 MiB" for a filesystem, which no operator can read.
func TestCapacitiesScaleButProcessMemoryStaysInMiB(t *testing.T) {
	report := model.Report{
		Host: model.Host{Hostname: "host", CPUCount: 8},
		Metrics: model.Metrics{
			Memory:      &model.Memory{TotalBytes: 512 << 30, AvailableBytes: 300 << 30, AvailableFraction: .58},
			Filesystems: []model.Filesystem{{MountPoint: "/data", Type: "xfs", TotalBytes: 40 << 40, AvailableBytes: 22 << 40, UsedFraction: .45}},
			Processes: &model.Processes{TopCPU: []model.Process{{PID: 1, Command: "worker", RSSBytes: 3 << 30}},
				TopRSS: []model.Process{{PID: 1, Command: "worker", RSSBytes: 3 << 30}}},
		},
		Score: model.Score{Value: 100, Status: model.SeverityOK, Label: "EXCELLENT"},
	}
	var out strings.Builder
	Write(&out, report, Options{Width: 120, Verbose: true})
	text := out.String()
	for _, want := range []string{"512.0 GiB", "22.0 TiB"} {
		if !strings.Contains(text, want) {
			t.Errorf("capacity not scaled, missing %q in:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "RAM 3072.0 MiB") {
		t.Errorf("process memory should stay comparable in MiB:\n%s", text)
	}
}

func TestSizeScalesAcrossUnits(t *testing.T) {
	cases := map[uint64]string{
		512:             "512 B",
		2048:            "2.0 KiB",
		5 << 20:         "5.0 MiB",
		3 << 30:         "3.0 GiB",
		uint64(7) << 40: "7.0 TiB",
		uint64(2) << 50: "2.0 PiB",
	}
	for value, want := range cases {
		if got := size(value); got != want {
			t.Errorf("size(%d)=%q want %q", value, got, want)
		}
	}
}

// Verbose rows carry text from external commands and must be sanitized like
// every other externally sourced string.
func TestVerboseExternalTextIsSanitized(t *testing.T) {
	report := model.Report{
		Host: model.Host{Hostname: "host", CPUCount: 1},
		Metrics: model.Metrics{
			NetworkState: &model.NetworkState{Available: true, RoutesAvailable: true,
				ListeningSockets: []model.ListeningSocket{{Protocol: "tcp\x1b[31m", Port: 22}},
				ConnectionStates: []model.ConnectionState{{State: "ESTAB\x1b[0m\nfake line", Count: 3}}},
			Security: &model.Security{Available: true, SELinux: "enforcing", AppArmor: "enabled",
				KernelTaintMask: 4097, KernelTaintModules: []string{"zfs\x1b[31m"}},
		},
		Score: model.Score{Value: 100, Status: model.SeverityOK, Label: "EXCELLENT"},
	}
	var out strings.Builder
	Write(&out, report, Options{Width: 200, Verbose: true})
	if strings.Contains(out.String(), "\x1b[31m") {
		t.Fatalf("unsanitized control sequence reached the terminal:\n%q", out.String())
	}
}

// A reduced-but-discovered path MTU is common (PPPoE, VPNs) and permanent
// for a given host, so its INFO row would otherwise reappear on every run
// forever; it stays quiet by default and only shows under --verbose. OK and
// WARN/CRIT rows for this same check are unaffected.
func TestPathMTUInfoRowHiddenUnlessVerbose(t *testing.T) {
	report := model.Report{
		Metrics:  model.Metrics{PathMTUCheck: &model.PathMTUCheck{Available: true, Target: "1.1.1.1", CeilingMTU: 1500, FloorMTU: 576, BaselineOK: true, DiscoveredMTU: 1420}},
		Findings: []model.Finding{{ID: "path-mtu-reduced", Severity: model.SeverityInfo, Category: "network", Title: "Path MTU is 1420 bytes, not 1500 -- this is normal, not a fault"}},
	}

	var compact strings.Builder
	Write(&compact, report, Options{})
	if strings.Contains(compact.String(), "Path MTU") {
		t.Fatalf("expected the Path MTU row to be hidden for an INFO-severity result in the default report:\n%s", compact.String())
	}

	var verbose strings.Builder
	Write(&verbose, report, Options{Verbose: true})
	if !strings.Contains(verbose.String(), "Path MTU") {
		t.Fatalf("expected the Path MTU row to still show under --verbose:\n%s", verbose.String())
	}
}

func TestPathMTUCriticalRowAlwaysShown(t *testing.T) {
	report := model.Report{
		Metrics:  model.Metrics{PathMTUCheck: &model.PathMTUCheck{Available: true, Target: "1.1.1.1", CeilingMTU: 1500, FloorMTU: 576, BaselineOK: true, DiscoveredMTU: 0}},
		Findings: []model.Finding{{ID: "path-mtu-blackhole", Severity: model.SeverityWarning, Category: "network", Title: "Possible path MTU black hole"}},
	}
	var out strings.Builder
	Write(&out, report, Options{})
	if !strings.Contains(out.String(), "Path MTU") {
		t.Fatalf("expected the Path MTU row to show by default when it found a real problem:\n%s", out.String())
	}
}

// An unrelated informational finding elsewhere in the broad "network"
// category (path MTU, DNS, gateway, HTTP, and TCP findings all share it for
// scoring) must not bump the Network and TCP summary badges to INFO when
// neither interface counters nor TCP counters actually have anything wrong.
func TestNetworkAndTCPBadgesIgnoreUnrelatedNetworkCategoryFindings(t *testing.T) {
	report := model.Report{
		Host: model.Host{Hostname: "host"},
		Metrics: model.Metrics{
			Network: []model.Network{{Name: "eth0"}},
			TCP:     &model.TCP{SegmentsOut: 100},
		},
		Findings: []model.Finding{
			{ID: "path-mtu-reduced", Severity: model.SeverityInfo, Category: "network", Title: "Path MTU is 1420 bytes, not 1500 -- this is normal, not a fault"},
			{ID: "dns-resolution-external-failed", Severity: model.SeverityCritical, Category: "network", Title: "External DNS server unreachable"},
		},
	}
	var out strings.Builder
	Write(&out, report, Options{ASCII: true})
	text := out.String()
	if !strings.Contains(text, "Network OK") {
		t.Fatalf("expected Network row to stay OK despite an unrelated network-category finding:\n%s", text)
	}
	if !strings.Contains(text, "TCP OK") {
		t.Fatalf("expected TCP row to stay OK despite an unrelated network-category finding:\n%s", text)
	}
}

// A finding that genuinely concerns an interface (elevated errors, a missing
// default route, conntrack drops) or TCP counters must still raise the
// matching row's badge.
func TestNetworkAndTCPBadgesReflectTheirOwnFindings(t *testing.T) {
	report := model.Report{
		Host:     model.Host{Hostname: "host"},
		Metrics:  model.Metrics{Network: []model.Network{{Name: "eth0"}}},
		Findings: []model.Finding{{ID: "network-no-default-route", Severity: model.SeverityInfo, Category: "network", Title: "No default route observed"}},
	}
	var out strings.Builder
	Write(&out, report, Options{ASCII: true})
	if !strings.Contains(out.String(), "Network INFO") {
		t.Fatalf("expected Network row to reflect its own finding:\n%s", out.String())
	}

	tcpReport := model.Report{
		Host:     model.Host{Hostname: "host"},
		Metrics:  model.Metrics{TCP: &model.TCP{SegmentsOut: 100, RetransmittedSegments: 40}},
		Findings: []model.Finding{{ID: "tcp-retransmits", Severity: model.SeverityWarning, Category: "network", Title: "Elevated TCP retransmissions"}},
	}
	var tcpOut strings.Builder
	Write(&tcpOut, tcpReport, Options{ASCII: true})
	if !strings.Contains(tcpOut.String(), "TCP WARN") {
		t.Fatalf("expected TCP row to reflect its own finding:\n%s", tcpOut.String())
	}
}

// --quiet drops rows that are fully healthy (OK) but keeps anything with
// something to say, plus the Details section and host header.
func TestQuietHidesOnlyOKRows(t *testing.T) {
	report := model.Report{
		Host: model.Host{Hostname: "host"},
		Metrics: model.Metrics{
			CPU:     &model.CPU{Load1: 0.1},
			Memory:  &model.Memory{AvailableFraction: 0.9, TotalBytes: 1 << 30, AvailableBytes: 900 << 20},
			Disks:   []model.Disk{{Name: "sda"}},
			Network: []model.Network{{Name: "eth0"}},
		},
		Findings: []model.Finding{{ID: "disk-contention-sda", Severity: model.SeverityCritical, Category: "disk", Title: "Disk contention"}},
	}
	var out strings.Builder
	Write(&out, report, Options{Quiet: true, ASCII: true})
	text := out.String()
	for _, mustNotContain := range []string{"CPU OK", "Memory OK", "Network OK"} {
		if strings.Contains(text, mustNotContain) {
			t.Errorf("quiet output should hide fully healthy rows, found %q:\n%s", mustNotContain, text)
		}
	}
	if !strings.Contains(text, "Disk CRIT") {
		t.Errorf("quiet output should keep rows with a problem:\n%s", text)
	}
	if !strings.Contains(text, "Disk contention") {
		t.Errorf("quiet output should keep the Details section:\n%s", text)
	}
	if !strings.Contains(text, "host") {
		t.Errorf("quiet output should keep the host header:\n%s", text)
	}
}

func TestQuietWithoutIssuesStillShowsHeaderAndNoFindingsLine(t *testing.T) {
	report := model.Report{
		Host:    model.Host{Hostname: "host"},
		Metrics: model.Metrics{CPU: &model.CPU{Load1: 0.1}},
	}
	var out strings.Builder
	Write(&out, report, Options{Quiet: true, ASCII: true})
	text := out.String()
	if strings.Contains(text, "CPU OK") {
		t.Errorf("quiet output should hide the healthy CPU row:\n%s", text)
	}
	if !strings.Contains(text, "No actionable findings") {
		t.Errorf("quiet output should still state that nothing actionable was found:\n%s", text)
	}
}
