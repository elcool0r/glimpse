// Package analyze turns normalized observations into conservative findings.
package analyze

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/model"
)

func Report(report *model.Report) {
	findings := make([]model.Finding, 0)
	m := report.Metrics
	if cpu := m.CPU; cpu != nil && (cpu.Sampled == nil || *cpu.Sampled) && cpu.Utilization >= cpuUtilizationWarning && cpu.Load1 > float64(max(1, report.Host.CPUCount)) && m.Pressure != nil && m.Pressure.CPU.SomeAvg10 >= cpuPressureWarning {
		findings = append(findings, findingWithDiagnostic("cpu-contention", model.SeverityWarning, "cpu", "Sustained CPU contention", fmt.Sprintf("CPU averaged %.0f%%, load was %.1f across %d CPUs, and CPU PSI some avg10 was %.1f%%.", cpu.Utilization*100, cpu.Load1, report.Host.CPUCount, m.Pressure.CPU.SomeAvg10), "Inspect runnable processes and CPU limits.", "ps aux --sort=-%cpu | head -11", 10))
	}
	if cpu := m.CPU; cpu != nil && (cpu.Sampled == nil || *cpu.Sampled) && cpu.Steal >= cpuStealWarning && m.Pressure != nil && m.Pressure.CPU.SomeAvg10 >= cpuStealPressure {
		findings = append(findings, findingWithDiagnostic("cpu-steal", model.SeverityWarning, "cpu", "CPU time lost to the hypervisor", fmt.Sprintf("Steal averaged %.1f%% during the sample and CPU PSI some avg10 was %.1f%%.", cpu.Steal*100, m.Pressure.CPU.SomeAvg10), "Inspect hypervisor contention and the VM CPU allocation.", "watch -n 1 'grep cpu /proc/stat'", 10))
	}

	if mem := m.Memory; mem != nil && memoryAvailable(mem) && mem.AvailableFraction < memoryAvailableWarning && ((m.Pressure != nil && m.Pressure.Memory.SomeAvg10 >= memoryPressureWarning) || mem.SwapInBytes > 0 || mem.SwapOutBytes > 0) {
		findings = append(findings, findingWithDiagnostic("memory-pressure", model.SeverityWarning, "memory", "Memory pressure observed", fmt.Sprintf("MemAvailable is %.1f%%; memory PSI some avg10 is %.1f%%; swap activity during the sample was %s.", mem.AvailableFraction*100, pressureMemory(m.Pressure), bytes(mem.SwapInBytes+mem.SwapOutBytes)), "Inspect top memory consumers and cgroup limits.", "ps aux --sort=-%mem | head -11", 12))
	}
	for _, fs := range m.Filesystems {
		if fs.ReadOnly {
			if strings.EqualFold(fs.Type, "squashfs") {
				continue
			}
			// The compact report shows only the title, so it has to identify
			// which mount it is about.
			findings = append(findings, finding("filesystem-read-only-"+fs.MountPoint, model.SeverityInfo, "filesystem", "Read-only filesystem: "+fs.MountPoint, fmt.Sprintf("%s (%s) is mounted read-only; this may be intentional.", fs.MountPoint, fs.Type), "Compare with the intended mount configuration and kernel filesystem events.", 0))
			continue
		}
		if fs.UsedFraction >= filesystemFull {
			cmd := fmt.Sprintf("du -sh %s/* 2>/dev/null | sort -rh | head -10", fs.MountPoint)
			findings = append(findings, findingWithDiagnostic("filesystem-"+fs.MountPoint, model.SeverityCritical, "filesystem", "Filesystem nearly full", fmt.Sprintf("%s (%s) is %.1f%% used.", fs.MountPoint, fs.Type, fs.UsedFraction*100), "Free space or review retention policies.", cmd, 20))
		} else if fs.UsedFraction >= filesystemWarning {
			cmd := fmt.Sprintf("du -sh %s/* 2>/dev/null | sort -rh | head -10", fs.MountPoint)
			findings = append(findings, findingWithDiagnostic("filesystem-"+fs.MountPoint, model.SeverityWarning, "filesystem", "Filesystem filling up", fmt.Sprintf("%s (%s) is %.1f%% used.", fs.MountPoint, fs.Type, fs.UsedFraction*100), "Review large files and retention policies.", cmd, 8))
		}
		if fs.InodesTotal > 0 && fs.InodesFree <= fs.InodesTotal {
			used := fraction(fs.InodesTotal-fs.InodesFree, fs.InodesTotal)
			if used >= inodeWarning {
				severity, impact := model.SeverityWarning, 8
				if used >= inodeFull {
					severity, impact = model.SeverityCritical, 20
				}
				cmd := fmt.Sprintf("df -i %s && find %s -maxdepth 1 -type d -exec bash -c 'printf \"%%s %%s\\\\n\" $(find \"{}\" -type f 2>/dev/null | wc -l) \"{}\"' \\; | sort -rn | head -10", fs.MountPoint, fs.MountPoint)
				findings = append(findings, findingWithDiagnostic("filesystem-inodes-"+fs.MountPoint, severity, "filesystem", "Filesystem inode capacity nearly exhausted", fmt.Sprintf("%s has %d of %d inodes free (%.1f%% used).", fs.MountPoint, fs.InodesFree, fs.InodesTotal, used*100), "Inspect directories with many small files and their retention policies.", cmd, impact))
			}
		}
	}
	for _, n := range m.Network {
		if !intervalSampled(n.Sampled) {
			continue
		}
		for _, direction := range []struct {
			name                             string
			packets, errors, drops, overruns uint64
		}{
			{"RX", n.RXPackets, n.RXErrors, n.RXDropped, n.RXFIFOErrors},
			{"TX", n.TXPackets, n.TXErrors, n.TXDropped, n.TXFIFOErrors},
		} {
			// A handful of drops without a meaningful ratio is not a host fault.
			// Overruns are judged the same way: like drops they follow load,
			// and a few on a busy interface say nothing.
			for _, signal := range []struct {
				name  string
				count uint64
			}{{"errors", direction.errors}, {"drops", direction.drops}, {"overruns", direction.overruns}} {
				ratio := float64(signal.count) / (float64(direction.packets) + float64(signal.count))
				if signal.count < networkMinimumEvents || ratio < networkWarningRatio {
					continue
				}
				cmd := fmt.Sprintf("ethtool -S %s 2>/dev/null | grep -i \"%s.*%s\" || ip -s link show %s", n.Name, direction.name, signal.name, n.Name)
				findings = append(findings, findingWithDiagnostic("network-"+n.Name+"-"+direction.name+"-"+signal.name, model.SeverityWarning, "network", "Elevated network "+signal.name, fmt.Sprintf("%s %s recorded %d %s alongside %d packets during the sample (%.1f%%).", n.Name, direction.name, signal.count, signal.name, direction.packets, ratio*100), "Inspect interface and peer counters; for drops and overruns, also inspect queues and application receive capacity.", cmd, 7))
			}
		}
		findings = append(findings, linkFindings(n)...)
	}
	for _, t := range m.Thermal {
		if t.CriticalC <= 0 {
			continue
		}
		// A fixed margin is applied to sensors whose critical points range from
		// ~60°C on drives to ~100°C on CPU packages. Warning on "within 5°C"
		// therefore fires on any CPU boosting near Tjmax, which is normal
		// operation. Only crossing the hardware's own limit is a warning.
		switch {
		case t.TemperatureC >= t.CriticalC:
			cmd := fmt.Sprintf("sensors 2>/dev/null | grep -A2 \"%s\"", t.Name)
			findings = append(findings, findingWithDiagnostic("thermal-"+t.Name, model.SeverityWarning, "thermal", "Temperature at or above critical limit", fmt.Sprintf("%s is %.1f°C (critical %.1f°C).", t.Name, t.TemperatureC, t.CriticalC), "Check cooling, airflow, and load; sustained operation at this temperature will throttle or damage hardware.", cmd, 10))
		case t.TemperatureC >= t.CriticalC-thermalMargin:
			cmd := fmt.Sprintf("sensors 2>/dev/null | grep -A2 \"%s\"", t.Name)
			findings = append(findings, findingWithDiagnostic("thermal-"+t.Name, model.SeverityInfo, "thermal", "Temperature approaching critical limit", fmt.Sprintf("%s is %.1f°C, within %.0f°C of its %.1f°C critical limit.", t.Name, t.TemperatureC, thermalMargin, t.CriticalC), "Expected under sustained load on many CPUs; check cooling and airflow if it persists at idle.", cmd, 0))
		}
	}
	if p := m.Processes; p != nil && p.Zombies > 0 {
		summary, suggestion := zombieDetails(p)
		findings = append(findings, finding("zombies", model.SeverityInfo, "process", zombieTitle(p), summary, suggestion, 0))
	}
	if p := m.Processes; p != nil && len(p.StuckProcesses) > 0 {
		f := endpointDStateFinding(p)
		f.DiagnosticCommand = "ps aux | grep -E ' D ' && lsof -p <pid> 2>/dev/null"
		findings = append(findings, f)
	}
	if s := m.Systemd; s != nil && len(s.FailedUnits) > 0 {
		findings = append(findings, findingWithDiagnostic("failed-units", model.SeverityCritical, "services", "Failed systemd units", failedUnitsSummary(s), "Run systemctl --failed and inspect the affected unit logs.", "systemctl --failed && systemctl status <unit>", 25))
	}
	if s := m.Systemd; s != nil {
		// A unit using Restart=always crash-looping never appears in
		// `systemctl --failed` -- systemd keeps restarting it, so it can
		// read as "active (running)" between crashes. A unit restarting at
		// all during a short observation window is already unusual; several
		// restarts in that same window is unambiguous crash-looping,
		// independent of whatever the CPU/memory/network metrics say.
		for _, u := range s.RestartingUnits {
			severity, impact := model.SeverityWarning, 15
			if u.RestartsDelta >= 3 {
				severity, impact = model.SeverityCritical, 25
			}
			cmd := fmt.Sprintf("journalctl -u %s --since '30 minutes ago' | tail -30", u.Unit)
			findings = append(findings, findingWithDiagnostic("systemd-restarting-"+u.Unit, severity, "services", fmt.Sprintf("Systemd unit %s is restarting repeatedly", u.Unit),
				fmt.Sprintf("%s restarted %d time(s) during the sampling window. A unit does not normally restart while being observed; this can mean the service is crash-looping even though it may show as active between restarts.", u.Unit, u.RestartsDelta),
				fmt.Sprintf("Inspect recent logs (journalctl -u %s) and the unit's exit status.", u.Unit), cmd, impact))
		}
	}
	if k := m.Kernel; k != nil {
		for _, event := range k.Events {
			var eventTime *time.Time
			if event.AgeSeconds != nil {
				t := report.GeneratedAt.Add(-time.Duration(*event.AgeSeconds) * time.Second)
				eventTime = &t
			}
			findings = append(findings, kernelFinding(event, eventTime))
		}
	}
	findings = append(findings, diskFindings(report)...)
	findings = append(findings, tcpFindings(m.TCP, m.Resources, m.IPv6Check)...)
	findings = append(findings, conntrackFindings(m.Conntrack)...)
	findings = append(findings, deviceHealthFindings(m.DeviceHealth)...)
	findings = append(findings, timeSyncFindings(m.TimeSync)...)
	findings = append(findings, resourceFindings(m.Resources)...)
	findings = append(findings, cgroupFindings(m.CgroupV2, m.Pressure)...)
	findings = append(findings, containerFindings(m.Containers)...)
	findings = append(findings, zfsFindings(m.ZFSPools)...)
	findings = append(findings, AnalyzeSecurity(report)...)
	findings = append(findings, backlogFindings(report)...)
	sort.Slice(findings, func(i, j int) bool { return rank(findings[i].Severity) > rank(findings[j].Severity) })
	report.Findings = findings
	if insufficientCoverage(report) {
		report.Score = model.Score{Value: 0, Status: model.SeverityUnknown, Label: "INSUFFICIENT DATA"}
		return
	}
	report.Score = scoreFindings(findings)
}

func failedUnitsSummary(systemd *model.Systemd) string {
	units := make([]string, 0, len(systemd.FailedUnits))
	for _, unit := range systemd.FailedUnits {
		label := unit
		if since, ok := systemd.FailedUnitSince[unit]; ok && !since.IsZero() {
			label = fmt.Sprintf("%s (since %s)", unit, since.Local().Format("15:04 2006-01-02"))
		}
		units = append(units, label)
	}
	return fmt.Sprintf("%d failed units: %v", len(units), units)
}

// scoreFindings subtracts each finding's impact, bounded per category so one
// noisy subsystem cannot floor the score and erase the distinction between a
// host with a single problem and a host with nothing left working.
func scoreFindings(findings []model.Finding) model.Score {
	spent := make(map[string]int)
	score := 100
	highest := model.SeverityOK
	for _, f := range findings {
		impact := f.ScoreImpact
		if remaining := categoryImpactCap - spent[f.Category]; impact > remaining {
			impact = remaining
		}
		if impact < 0 {
			impact = 0
		}
		spent[f.Category] += impact
		score -= impact
		if rank(f.Severity) > rank(highest) {
			highest = f.Severity
		}
	}
	if score < 0 {
		score = 0
	}
	return model.Score{Value: score, Status: highest, Label: label(score, highest)}
}

func zombieDetails(processes *model.Processes) (string, string) {
	if len(processes.ZombieProcesses) == 0 {
		return fmt.Sprintf("%d zombie processes were observed, but process identities were unavailable.", processes.Zombies), "Run ps -eo pid,ppid,stat,comm | awk '$3 ~ /^Z/' to identify their parents."
	}
	items := make([]string, 0, len(processes.ZombieProcesses))
	for _, process := range processes.ZombieProcesses {
		item := fmt.Sprintf("PID %d (%s)", process.PID, process.Command)
		if process.ParentPID > 0 {
			item += fmt.Sprintf(", parent PID %d", process.ParentPID)
			if process.ParentCommand != "" {
				item += " (" + process.ParentCommand + ")"
			}
		}
		items = append(items, item)
	}
	more := ""
	if processes.Zombies > len(processes.ZombieProcesses) {
		more = fmt.Sprintf("; %d additional zombie process(es) omitted", processes.Zombies-len(processes.ZombieProcesses))
	}
	first := processes.ZombieProcesses[0]
	suggestion := "Inspect the listed parent process; restart or fix it only if it is not expected to reap the child."
	if first.ParentPID > 0 {
		suggestion = fmt.Sprintf("Inspect parent PID %d with ps -fp %d; restart or fix that parent only if it is not expected to reap the child.", first.ParentPID, first.ParentPID)
	}
	return fmt.Sprintf("%d zombie process(es): %s%s.", processes.Zombies, strings.Join(items, "; "), more), suggestion
}

// endpointDStateFinding reports process identities observed in D state at
// both sampling boundaries without inferring their state between endpoints.
func endpointDStateFinding(processes *model.Processes) model.Finding {
	items := make([]string, 0, len(processes.StuckProcesses))
	for _, process := range processes.StuckProcesses {
		item := fmt.Sprintf("PID %d (%s)", process.PID, process.Command)
		if process.ParentPID > 0 {
			item += fmt.Sprintf(", parent PID %d", process.ParentPID)
		}
		items = append(items, item)
	}
	return finding("process-stuck-uninterruptible", model.SeverityInfo, "process", "Processes observed in uninterruptible sleep (D state) at both boundaries",
		fmt.Sprintf("%d process(es) were observed in D state at both sampling boundaries: %s. Endpoint observations do not establish continuous D-state residency between them.", len(processes.StuckProcesses), strings.Join(items, "; ")),
		"Inspect the affected process and its storage or NFS dependencies if the condition recurs or host I/O pressure is elevated.", 0)
}

func zombieTitle(processes *model.Processes) string {
	if len(processes.ZombieProcesses) == 0 {
		return "Zombie processes present"
	}
	items := make([]string, 0, len(processes.ZombieProcesses))
	for _, process := range processes.ZombieProcesses {
		item := fmt.Sprintf("PID %d (%s)", process.PID, process.Command)
		if process.ParentPID > 0 {
			item += fmt.Sprintf(", parent PID %d", process.ParentPID)
			if process.ParentCommand != "" {
				item += " (" + process.ParentCommand + ")"
			}
		}
		items = append(items, item)
	}
	return "Zombie: " + strings.Join(items, "; ")
}

func cgroupFindings(cgroup *model.CgroupV2, _ *model.Pressure) []model.Finding {
	if cgroup == nil || !cgroup.Available {
		return nil
	}
	var findings []model.Finding
	if cgroupValid(cgroup.MemoryEventsSampled) && cgroup.MemoryOOMKillDelta > 0 {
		findings = append(findings, findingWithDiagnostic("cgroup-oom-kill", model.SeverityCritical, "cgroup", "Cgroup OOM kills during sample", fmt.Sprintf("The current cgroup recorded %d OOM kill(s) during the sampling window.", cgroup.MemoryOOMKillDelta), "Inspect the workload's memory limit and the largest memory consumers.", "systemctl show --property=MemoryLimit --value <unit> 2>/dev/null || cat /sys/fs/cgroup/memory/memory.max_usage_in_bytes", 25))
	} else if cgroupValid(cgroup.MemoryEventsSampled) && cgroup.MemoryOOMDelta > 0 {
		findings = append(findings, findingWithDiagnostic("cgroup-oom", model.SeverityWarning, "cgroup", "Cgroup memory allocation failures", fmt.Sprintf("The current cgroup recorded %d memory OOM event(s) during the sampling window.", cgroup.MemoryOOMDelta), "Inspect the workload's memory limit and memory demand.", "systemctl show --property=MemoryLimit --value <unit> 2>/dev/null || cat /sys/fs/cgroup/memory/memory.max_usage_in_bytes", 15))
	}
	if cgroupValid(cgroup.CPUStatSampled) && cgroup.CPUUsageSecondsDelta >= .1 && cgroup.CPUThrottledSecondsDelta >= .1 && cgroup.CPUThrottledSecondsDelta/cgroup.CPUUsageSecondsDelta >= .10 {
		findings = append(findings, findingWithDiagnostic("cgroup-cpu-throttling", model.SeverityWarning, "cgroup", "Cgroup CPU quota throttling", fmt.Sprintf("The current cgroup spent %.1fs throttled while using %.1fs CPU during the sample.", cgroup.CPUThrottledSecondsDelta, cgroup.CPUUsageSecondsDelta), "Inspect the CPU quota and runnable workload in this cgroup.", "systemctl show --property=CPUQuotaPerSecUSec --value <unit> 2>/dev/null || cat /sys/fs/cgroup/cpu/cpu.stat | grep throttled", 10))
	}
	if cgroupValid(cgroup.PIDsCurrentValid) && cgroupValid(cgroup.PIDsMaxValid) && cgroup.PIDsMax != nil && *cgroup.PIDsMax > 0 && fraction(cgroup.PIDsCurrent, *cgroup.PIDsMax) >= .95 {
		findings = append(findings, findingWithDiagnostic("cgroup-pids-limit", model.SeverityWarning, "cgroup", "Cgroup PID limit nearly exhausted", fmt.Sprintf("The current cgroup uses %d of %d allowed PIDs.", cgroup.PIDsCurrent, *cgroup.PIDsMax), "Inspect process growth and raise the cgroup PID limit only if demand is expected.", "ps --cgroup <cgroup-path> -eo pid,cmd | wc -l", 10))
	}
	if cgroupValid(cgroup.MemoryCurrentValid) && cgroupValid(cgroup.MemoryMaxValid) && cgroup.MemoryMaxBytes != nil && *cgroup.MemoryMaxBytes > 0 && fraction(cgroup.MemoryCurrentBytes, *cgroup.MemoryMaxBytes) >= .95 && ((cgroupValid(cgroup.MemoryEventsSampled) && (cgroup.MemoryOOMDelta > 0 || cgroup.MemoryOOMKillDelta > 0)) || (cgroupValid(cgroup.MemoryPressureValid) && cgroup.MemoryPressure != nil && cgroup.MemoryPressure.SomeAvg10 >= 1)) {
		findings = append(findings, findingWithDiagnostic("cgroup-memory-limit", model.SeverityWarning, "cgroup", "Cgroup memory limit under pressure", fmt.Sprintf("The current cgroup uses %.1f%% of its %s memory limit with corroborating memory pressure.", fraction(cgroup.MemoryCurrentBytes, *cgroup.MemoryMaxBytes)*100, bytes(*cgroup.MemoryMaxBytes)), "Inspect the cgroup memory limit and workload memory demand.", "systemctl show --property=MemoryLimit --value <unit> 2>/dev/null && ps aux --sort=-%mem | head -11", 12))
	}
	return findings
}

// Nil validity retains compatibility with legacy hand-built reports and
// schema-v1 JSON. Collectors use explicit false to suppress conclusions from
// unavailable or malformed cgroup files.
func cgroupValid(valid *bool) bool { return valid == nil || *valid }

func containerFindings(runtimes []model.ContainerRuntime) []model.Finding {
	var findings []model.Finding
	for _, runtime := range runtimes {
		for _, container := range runtime.Containers {
			name := container.Name
			if name == "" {
				name = container.ID
			}
			prefix := "container-" + runtime.Runtime + "-" + name
			if container.OOMKilled {
				cmd := fmt.Sprintf("%s inspect %s --format='{{.HostConfig.Memory}}'", runtime.Runtime, name)
				findings = append(findings, findingWithDiagnostic(prefix+"-oom", model.SeverityCritical, "containers", "Container was OOM-killed", fmt.Sprintf("%s container %s reports an OOM-killed state.", runtime.Runtime, name), "Inspect its memory limit, recent logs, and workload memory demand.", cmd, 20))
			}
			if container.Healthy != nil && !*container.Healthy {
				cmd := fmt.Sprintf("%s inspect %s --format='{{.State.Health.Status}}'", runtime.Runtime, name)
				findings = append(findings, findingWithDiagnostic(prefix+"-unhealthy", model.SeverityWarning, "containers", "Container health check is failing", fmt.Sprintf("%s container %s is marked unhealthy.", runtime.Runtime, name), "Inspect the container health check and recent application logs.", cmd, 12))
			}
			if container.RestartCount > 0 {
				severity, impact := model.SeverityWarning, 12
				if container.RestartCount >= 3 {
					severity, impact = model.SeverityCritical, 20
				}
				cmd := fmt.Sprintf("%s logs --tail 30 %s", runtime.Runtime, name)
				findings = append(findings, findingWithDiagnostic(prefix+"-restarts", severity, "containers", "Container restarted during sample", fmt.Sprintf("%s container %s restarted %d time(s) during the sampling window.", runtime.Runtime, name, container.RestartCount), "Inspect exit status and recent application logs.", cmd, impact))
			}
			if strings.EqualFold(container.State, "exited") && container.HasRestartPolicy {
				cmd := fmt.Sprintf("%s logs --tail 20 %s", runtime.Runtime, name)
				findings = append(findings, findingWithDiagnostic(prefix+"-exited", model.SeverityWarning, "containers", "Restart-managed container is exited", fmt.Sprintf("%s container %s is exited despite a restart policy.", runtime.Runtime, name), "Inspect exit status, runtime events, and the restart policy.", cmd, 10))
			}
			// A log line containing the word "error" is not a failure. Matching
			// it as one turned an HTTP path, a package name and a successful
			// retry into warnings, which is enough to make the exit code
			// meaningless on any host running containers. Concrete failure
			// signatures still warn; generic matches are kept as evidence at
			// informational severity so they remain visible without moving the
			// score.
			specific, generic := partitionLogEvents(container.LogEvents)
			if len(specific) > 0 {
				cmd := fmt.Sprintf("%s logs --since 1h --timestamps %s 2>/dev/null | grep -iE 'oom|segmentation|panic|abort|signal'", runtime.Runtime, name)
				findings = append(findings, model.Finding{
					ID:                prefix + "-log-events",
					Severity:          model.SeverityWarning,
					Category:          "containers",
					Title:             "Container log reports a failure",
					Summary:           fmt.Sprintf("%s container %s logged %s in the last hour.", runtime.Runtime, name, describeLogKinds(specific)),
					Evidence:          logEvidence(specific),
					DiagnosticCommand: cmd,
					ScoreImpact:       8,
				})
			} else if len(generic) > 0 {
				cmd := fmt.Sprintf("%s logs --since 1h --timestamps %s 2>/dev/null | head -20", runtime.Runtime, name)
				findings = append(findings, model.Finding{
					ID:                prefix + "-log-messages",
					Severity:          model.SeverityInfo,
					Category:          "containers",
					Title:             fmt.Sprintf("Container %s logged %d error/failure line(s)", name, len(generic)),
					Summary:           fmt.Sprintf("%s container %s logged lines matching generic error wording; this is context, not a detected fault.", runtime.Runtime, name),
					Evidence:          logEvidence(generic),
					DiagnosticCommand: cmd,
					ScoreImpact:       0,
				})
			}
		}
	}
	return findings
}

// specificLogKind marks classifications that identify a concrete failure.
// The generic "error" and "failure" kinds match ordinary application wording
// and cannot support a health verdict on their own.
func specificLogKind(kind string) bool {
	switch kind {
	case "oom", "panic", "segmentation_fault", "uncaught_exception",
		"data_corruption", "read_only_filesystem":
		return true
	default:
		return false
	}
}

func partitionLogEvents(events []model.LogEvent) (specific, generic []model.LogEvent) {
	for _, event := range events {
		if specificLogKind(event.Kind) {
			specific = append(specific, event)
			continue
		}
		generic = append(generic, event)
	}
	return specific, generic
}

func describeLogKinds(events []model.LogEvent) string {
	seen := make(map[string]struct{}, len(events))
	kinds := make([]string, 0, len(events))
	for _, event := range events {
		if _, ok := seen[event.Kind]; ok {
			continue
		}
		seen[event.Kind] = struct{}{}
		kinds = append(kinds, strings.ReplaceAll(event.Kind, "_", " "))
	}
	sort.Strings(kinds)
	return strings.Join(kinds, ", ")
}

func logEvidence(events []model.LogEvent) []model.Evidence {
	evidence := make([]model.Evidence, 0, len(events))
	for _, event := range events {
		evidence = append(evidence, model.Evidence{Value: event.Message})
	}
	return evidence
}

func zfsFindings(pools []model.ZFSPool) []model.Finding {
	var findings []model.Finding
	for _, pool := range pools {
		if strings.Contains(strings.ToLower(pool.ScanState), "in progress") {
			cmd := fmt.Sprintf("zpool status -v %s 2>/dev/null | grep -E 'scan:|state:'", pool.Name)
			findings = append(findings, findingWithDiagnostic("zfs-pool-"+pool.Name+"-scan", model.SeverityInfo, "zfs", "ZFS maintenance scan is running", fmt.Sprintf("Pool %s: %s", pool.Name, pool.ScanState), "Monitor zpool status for completion; temporary extra disk activity is expected.", cmd, 0))
		}
		if pool.Health != "" && !strings.EqualFold(pool.Health, "ONLINE") {
			cmd := fmt.Sprintf("zpool status -v %s 2>/dev/null | head -40", pool.Name)
			findings = append(findings, findingWithDiagnostic("zfs-pool-"+pool.Name+"-health", model.SeverityCritical, "zfs", "ZFS pool is not ONLINE", fmt.Sprintf("Pool %s reports health %s.", pool.Name, pool.Health), "Run zpool status -v and repair or replace affected devices before relying on the pool.", cmd, 30))
			continue
		}
		if pool.PermanentErrors {
			cmd := fmt.Sprintf("zpool status -v %s 2>/dev/null | grep -E 'state:|error'", pool.Name)
			findings = append(findings, findingWithDiagnostic("zfs-pool-"+pool.Name+"-permanent-errors", model.SeverityCritical, "zfs", "ZFS reports permanent data errors", fmt.Sprintf("Pool %s is ONLINE but zpool status reports permanent data errors.", pool.Name), "Restore affected data from backup and investigate zpool status -v immediately.", cmd, 30))
			continue
		}
		if zfsPoolHasErrors(pool) {
			findings = append(findings, zfsErrorFinding(pool))
		}
	}
	return findings
}

func zfsPoolHasErrors(pool model.ZFSPool) bool {
	if pool.ReadErrors > 0 || pool.WriteErrors > 0 || pool.ChecksumErrors > 0 {
		return true
	}
	for _, vdev := range pool.VdevErrors {
		if vdev.ReadErrors > 0 || vdev.WriteErrors > 0 || vdev.ChecksumErrors > 0 {
			return true
		}
	}
	return false
}

func zfsErrorFinding(pool model.ZFSPool) model.Finding {
	summary := fmt.Sprintf("Pool %s root row has %d read, %d write, and %d checksum errors.", pool.Name, pool.ReadErrors, pool.WriteErrors, pool.ChecksumErrors)
	if len(pool.VdevErrors) > 0 {
		parts := make([]string, 0, len(pool.VdevErrors))
		for _, vdev := range pool.VdevErrors {
			parts = append(parts, fmt.Sprintf("%s (%s: %d read, %d write, %d checksum)", vdev.Name, vdev.State, vdev.ReadErrors, vdev.WriteErrors, vdev.ChecksumErrors))
		}
		summary += " Affected vdevs: " + strings.Join(parts, "; ") + "."
	}
	if pool.Approximate || zfsVdevApproximate(pool.VdevErrors) {
		summary += " Some counters use approximate scaled values."
	}
	cmd := fmt.Sprintf("zpool status -v %s 2>/dev/null | grep -E 'FAULTED|OFFLINE|errors|checksum'", pool.Name)
	return findingWithDiagnostic("zfs-pool-"+pool.Name+"-io-errors", model.SeverityWarning, "zfs", "ZFS pool reports device errors", summary, "Run zpool status -v and inspect the affected device path and cables.", cmd, 15)
}

func zfsVdevApproximate(vdevs []model.ZFSVdevError) bool {
	for _, vdev := range vdevs {
		if vdev.Approximate {
			return true
		}
	}
	return false
}

func diskFindings(report *model.Report) []model.Finding {
	var findings []model.Finding
	for _, disk := range report.Metrics.Disks {
		if !intervalSampled(disk.Sampled) {
			continue
		}
		// Throughput alone is not a failure. Require saturation and a latency or
		// queueing symptom, plus independent host pressure before warning.
		queued := disk.AverageQueueDepth >= 2 || disk.AverageLatencyMillis >= 50
		pressure := report.Metrics.Pressure != nil && report.Metrics.Pressure.IO.SomeAvg10 >= 1
		iowait := report.Metrics.CPU != nil && (report.Metrics.CPU.Sampled == nil || *report.Metrics.CPU.Sampled) && report.Metrics.CPU.IOWait >= .10
		blocked := report.Metrics.CPU != nil && report.Metrics.CPU.Blocked > 0
		if disk.Utilization < .85 || !queued || !(pressure || iowait || blocked) {
			continue
		}
		severity, impact := model.SeverityWarning, 14
		if disk.Utilization >= .95 && disk.AverageQueueDepth >= 4 && (pressure || iowait) {
			severity, impact = model.SeverityCritical, 24
		}
		corroboration := "blocked tasks"
		if pressure && iowait {
			corroboration = "I/O pressure and elevated iowait"
		} else if pressure {
			corroboration = "I/O pressure"
		} else if iowait {
			corroboration = "elevated iowait"
		}
		cmd := fmt.Sprintf("iostat -xz 1 3 2>/dev/null | grep %s", disk.Name)
		findings = append(findings, findingWithDiagnostic("disk-contention-"+disk.Name, severity, "disk", "Storage I/O contention", fmt.Sprintf("%s was %.0f%% busy with an average queue depth of %.1f and %.1f ms average I/O latency; additional evidence: %s.", disk.Name, disk.Utilization*100, disk.AverageQueueDepth, disk.AverageLatencyMillis, corroboration), "Inspect the busiest processes, device latency, and underlying storage path.", cmd, impact))
	}
	return findings
}

// linkFindings judges the counters that describe the physical link rather than
// load. Frame errors, carrier losses and collisions are not a function of
// traffic volume, so they are judged by count instead of by ratio: a healthy
// full-duplex link should record none of them at all.
func linkFindings(n model.Network) []model.Finding {
	findings := make([]model.Finding, 0, 2)
	if n.RXFrameErrors+n.TXCarrierErrors >= networkMinimumEvents {
		cmd := fmt.Sprintf("ethtool -S %s 2>/dev/null | grep -E 'rx_frame|tx_carrier' || cat /proc/net/dev | grep %s", n.Name, n.Name)
		findings = append(findings, findingWithDiagnostic("network-"+n.Name+"-link-errors", model.SeverityWarning, "network", "Physical link errors",
			fmt.Sprintf("%s recorded %d frame errors and %d carrier losses during the sample.", n.Name, n.RXFrameErrors, n.TXCarrierErrors),
			"Inspect the cable, the transceiver or SFP, and the counters on the switch port.", cmd, 8))
	}
	// Collisions are normal on a half-duplex segment and carry no fault there.
	// On a link the driver reports as full duplex they are the classic symptom
	// of a duplex mismatch with the switch port.
	if n.Collisions >= networkMinimumEvents && strings.EqualFold(strings.TrimSpace(n.Duplex), "full") {
		cmd := fmt.Sprintf("ethtool %s 2>/dev/null | grep -E 'Speed|Duplex' && ethtool -S %s 2>/dev/null | grep collisions", n.Name, n.Name)
		findings = append(findings, findingWithDiagnostic("network-"+n.Name+"-collisions", model.SeverityWarning, "network", "Collisions on a full-duplex link",
			fmt.Sprintf("%s negotiated full duplex but recorded %d collisions during the sample.", n.Name, n.Collisions),
			"Compare the duplex setting on this interface with the switch port; a mismatch is the usual cause.", cmd, 8))
	}
	return findings
}

// conntrackFindings reports packets netfilter has already discarded. This is a
// separate signal from table utilization: a burst can exhaust the table and
// drop packets while the steady-state count that utilization measures still
// looks calm, so a host can drop traffic without ever tripping the capacity
// rule.
func conntrackFindings(conntrack *model.Conntrack) []model.Finding {
	if conntrack == nil {
		return nil
	}
	total := conntrack.Drops + conntrack.EarlyDrops + conntrack.InsertFailed
	if total == 0 {
		return nil
	}
	cmd := "sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max 2>/dev/null && conntrack -L 2>/dev/null | wc -l"
	return []model.Finding{findingWithDiagnostic("conntrack-drops", model.SeverityWarning, "network", "Connection tracking dropped packets",
		fmt.Sprintf("Netfilter recorded %d drops, %d early drops, and %d failed inserts during the sample.", conntrack.Drops, conntrack.EarlyDrops, conntrack.InsertFailed),
		"Inspect the connection rate against nf_conntrack_max and the conntrack timeouts for the busiest protocol.", cmd, 12)}
}

func tcpFindings(tcp *model.TCP, resources *model.Resources, ipv6 *model.IPv6Check) []model.Finding {
	if tcp == nil {
		return nil
	}
	var findings []model.Finding
	if intervalSampled(tcp.Sampled) {
		if tcp.SegmentsOut >= 100 && fraction(tcp.RetransmittedSegments, tcp.SegmentsOut) >= .02 {
			severity, impact := model.SeverityWarning, 10
			if fraction(tcp.RetransmittedSegments, tcp.SegmentsOut) >= .10 {
				severity, impact = model.SeverityCritical, 20
			}
			summary := fmt.Sprintf("%d of %d outbound TCP segments were retransmitted during the sample (%.1f%%).", tcp.RetransmittedSegments, tcp.SegmentsOut, fraction(tcp.RetransmittedSegments, tcp.SegmentsOut)*100)
			suggestion := "Inspect packet loss, interface counters, and the remote path."
			// This counter is system-wide, not per-connection: any application that
			// races a connection over IPv6 before falling back to IPv4 (or simply
			// prefers IPv6 and never falls back) contributes its unanswered SYN
			// retries to it too. When IPv6 is already reported unreachable, that is
			// usually the more likely explanation and the one to fix first, rather
			// than a separate, unrelated path problem.
			if ipv6 != nil && ipv6.Available && ipv6.Sent > 0 && ipv6.Received == 0 {
				summary += " This host's external IPv6 reachability check also failed during this sample; if any of this traffic was connections racing over IPv6 before falling back to IPv4, that alone can produce this many retransmits."
				suggestion = "Fix or disable IPv6 first (see the IPv6 finding) and recheck this counter; if it persists afterward, then inspect packet loss, interface counters, and the remote path."
			}
			cmd := "ss -i 2>/dev/null | head -10 || netstat -s 2>/dev/null | grep retransmit"
			findings = append(findings, findingWithDiagnostic("tcp-retransmits", severity, "network", "Elevated TCP retransmissions", summary, suggestion, cmd, impact))
		}
		if tcp.ListenOverflows+tcp.ListenDrops > 0 {
			// Naming somaxconn turns the finding from an observation into a number
			// the reader can act on, since it is the ceiling every listener's
			// requested backlog is silently capped to.
			ceiling := ""
			if resources != nil && resources.ListenBacklogMaximum > 0 {
				ceiling = fmt.Sprintf(" net.core.somaxconn is %d.", resources.ListenBacklogMaximum)
			}
			cmd := "ss -ltn 2>/dev/null | head -15 || netstat -s 2>/dev/null | grep listen"
			findings = append(findings, findingWithDiagnostic("tcp-listen-overflow", model.SeverityWarning, "network", "TCP listen queue overflow", fmt.Sprintf("The kernel recorded %d listen overflows or drops during the sample.%s", tcp.ListenOverflows+tcp.ListenDrops, ceiling), "Inspect the affected listener's backlog, accept rate, and file descriptor limits.", cmd, 12))
		}
		if opens := tcp.ActiveOpens + tcp.PassiveOpens; opens >= 50 && fraction(tcp.AttemptFails, opens) >= .10 {
			cmd := "ss -tn 2>/dev/null | head -20 || netstat -an | grep ESTAB"
			findings = append(findings, findingWithDiagnostic("tcp-connect-failures", model.SeverityWarning, "network", "Elevated TCP connection failures", fmt.Sprintf("%d of %d TCP connection attempts failed during the sample.", tcp.AttemptFails, opens), "Inspect destination availability, DNS, firewall rules, and application logs.", cmd, 8))
		}
	}
	// Socket tables have explicit kernel ceilings, which is what makes a
	// "large" socket count judgeable at all. An absolute threshold without one
	// would fire on every busy host.
	if resources != nil {
		for _, limit := range []struct {
			id, title, advice, cmd string
			current, maximum       uint64
		}{
			{"tcp-time-wait-saturation", "TIME_WAIT table nearly exhausted", "Inspect connection churn and whether clients reuse connections; the kernel discards the oldest entries once the bucket is full.", "ss -tan 2>/dev/null | grep TIME-WAIT | wc -l", tcp.TimeWaitSockets, resources.TimeWaitMaximum},
			{"tcp-orphan-saturation", "Orphaned socket table nearly exhausted", "Inspect applications abandoning sockets with unsent data; the kernel resets orphans once the limit is reached.", "netstat -an 2>/dev/null | grep -E 'FIN_WAIT|CLOSE_WAIT' | wc -l", tcp.OrphanSockets, resources.OrphanMaximum},
		} {
			if limit.maximum == 0 || fraction(limit.current, limit.maximum) < resourceWarning {
				continue
			}
			findings = append(findings, findingWithDiagnostic(limit.id, model.SeverityWarning, "network", limit.title,
				fmt.Sprintf("%d of %d entries are in use (%.0f%%).", limit.current, limit.maximum, fraction(limit.current, limit.maximum)*100),
				limit.advice, limit.cmd, 10))
		}
	}
	return findings
}

// intervalSampled keeps pre-validity reports compatible: only an explicit
// false means that counter deltas were unavailable at one sampling boundary.
func intervalSampled(sampled *bool) bool { return sampled == nil || *sampled }

// memoryAvailable preserves compatibility with older reports, where the
// absence of an explicit validity marker represented a measured value.
func memoryAvailable(memory *model.Memory) bool {
	return memory.AvailableValid == nil || *memory.AvailableValid
}

func deviceHealthFindings(devices []model.DeviceHealth) []model.Finding {
	var findings []model.Finding
	for _, device := range devices {
		if device.OverallPassed != nil && !*device.OverallPassed || device.CriticalWarning != 0 || device.PendingSectors != 0 || device.Uncorrectable != 0 || device.MediaErrors != 0 {
			cmd := fmt.Sprintf("smartctl -a /dev/%s 2>/dev/null | grep -E 'FAILED|Health Status|Critical Warning' || nvme smart-log /dev/%s", device.Device, device.Device)
			findings = append(findings, findingWithDiagnostic("device-health-"+device.Device, model.SeverityCritical, "disk", "Device health requires attention", fmt.Sprintf("%s reported a SMART/NVMe health failure or uncorrectable media error.", device.Device), "Back up important data and inspect the device's SMART/NVMe log promptly.", cmd, 25))
			continue
		}
		if device.AvailableSpare > 0 && device.AvailableSpare < .10 || device.PercentageUsed >= .95 {
			cmd := fmt.Sprintf("smartctl -a /dev/%s 2>/dev/null | grep -iE 'Spare|Wear|Reallocated|Media' || nvme smart-log /dev/%s", device.Device, device.Device)
			findings = append(findings, findingWithDiagnostic("device-wear-"+device.Device, model.SeverityWarning, "disk", "Device endurance is nearly exhausted", fmt.Sprintf("%s reports %.0f%% spare remaining and %.0f%% endurance used.", device.Device, device.AvailableSpare*100, device.PercentageUsed*100), "Plan replacement and verify current backups.", cmd, 14))
		}
	}
	return findings
}

func timeSyncFindings(sync *model.TimeSync) []model.Finding {
	if sync == nil || !sync.Available {
		return nil
	}
	if sync.Synchronized != nil && !*sync.Synchronized {
		cmd := "timedatectl status || ntpq -p 2>/dev/null || chronyc tracking 2>/dev/null"
		return []model.Finding{findingWithDiagnostic("time-unsynchronized", model.SeverityWarning, "time", "System clock is not synchronized", fmt.Sprintf("%s reports that the system clock is unsynchronized.", sync.Service), "Inspect the time synchronization service, sources, and network reachability.", cmd, 10)}
	}
	if sync.OffsetMillis != nil && abs(*sync.OffsetMillis) >= 1000 {
		severity, impact := model.SeverityWarning, 8
		if abs(*sync.OffsetMillis) >= 5000 {
			severity, impact = model.SeverityCritical, 16
		}
		cmd := "timedatectl status || ntpq -p 2>/dev/null || chronyc tracking 2>/dev/null"
		return []model.Finding{findingWithDiagnostic("time-offset", severity, "time", "Large clock offset", fmt.Sprintf("%s reports an offset of %.0f ms.", sync.Service, *sync.OffsetMillis), "Inspect time sources and correct clock synchronization before relying on timestamps.", cmd, impact)}
	}
	return nil
}

func resourceFindings(resources *model.Resources) []model.Finding {
	if resources == nil {
		return nil
	}
	var findings []model.Finding
	// The task count from /proc/loadavg counts threads, so it is measured
	// against the lower of threads-max and pid_max rather than against pid_max
	// alone, which is a highest-PID value and not a limit on task count.
	// The inotify watch count has no global kernel counter, so no usage rule
	// exists for it; only its limits are reported as capacity facts.
	for _, limit := range []struct {
		id, title, cmd   string
		current, maximum uint64
	}{
		{"file-descriptors", "File descriptor capacity nearly exhausted", "lsof -p $$ 2>/dev/null | wc -l || cat /proc/sys/fs/file-nr", resources.OpenFiles, resources.OpenFilesMaximum},
		{"tasks", "Process and thread capacity nearly exhausted", "ps -eLf 2>/dev/null | wc -l || cat /proc/sys/kernel/pid_max", resources.Processes, taskCeiling(resources)},
		{"conntrack", "Conntrack table nearly exhausted", "sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max 2>/dev/null", resources.Conntrack, resources.ConntrackMaximum},
	} {
		if limit.maximum == 0 || fraction(limit.current, limit.maximum) < resourceWarning {
			continue
		}
		severity, impact := model.SeverityWarning, 12
		if fraction(limit.current, limit.maximum) >= resourceFull {
			severity, impact = model.SeverityCritical, 20
		}
		findings = append(findings, findingWithDiagnostic("resource-"+limit.id, severity, "resources", limit.title, fmt.Sprintf("%d of %d (%0.f%%) are currently in use.", limit.current, limit.maximum, fraction(limit.current, limit.maximum)*100), "Identify consumers and raise the limit only after confirming expected demand.", limit.cmd, impact))
	}
	return findings
}

// kernelFinding weighs a journal record by kind and by age. The journal scan
// covers the current boot up to 24 hours, so without an age an incident from
// overnight reads exactly as urgently as one happening now.
func kernelFinding(event model.LogEvent, eventTime *time.Time) model.Finding {
	// A link coming back up is the recovery half of a link_down/link_up
	// pair, not a fault on its own -- reporting it as a Warning would
	// penalize a host for a NIC that already fixed itself.
	if event.Kind == "link_up" {
		summary := event.Message
		if event.AgeSeconds != nil {
			summary = fmt.Sprintf("%s (recorded %s ago)", summary, humanDuration(time.Duration(*event.AgeSeconds)*time.Second))
		}
		cmd := kernelDiagnosticCommand(event.Kind, eventTime)
		return findingWithEventTime("kernel-"+event.Kind, model.SeverityInfo, "kernel", "Kernel event: "+event.Kind, summary, "No action needed; this reports when the link came back up.", cmd, eventTime, 0)
	}
	severity, impact := model.SeverityWarning, 12
	if criticalKernelEvent(event.Kind) {
		severity, impact = model.SeverityCritical, 25
	}
	summary := event.Message
	suggestion := "Inspect the kernel journal and affected hardware or workload."

	switch event.Kind {
	case "oom":
		suggestion = "Inspect the kernel journal and affected processes using the diagnostic command above."
	case "panic":
		suggestion = "Inspect the panic message and system state using the diagnostic command above."
	case "oops":
		suggestion = "Inspect the oops details and kernel module state using the diagnostic command above."
	case "cgroup_oom":
		suggestion = "Inspect cgroup OOM events and container/workload memory limits."
	case "hardware_error":
		suggestion = "Inspect hardware error details and EDAC counters."
	case "filesystem_corruption":
		suggestion = "Run filesystem check and restore from backup if necessary."
	case "filesystem_readonly_remount":
		suggestion = "Inspect filesystem error details and attempt remount."
	case "disk_full":
		suggestion = "Free disk space and investigate the cause."
	}

	if event.AgeSeconds != nil {
		age := time.Duration(*event.AgeSeconds) * time.Second
		if age > kernelEventRecent {
			// Still reported, and still evidence, but one step down: the
			// record describes something that happened, not something
			// happening.
			if severity == model.SeverityCritical {
				severity, impact = model.SeverityWarning, 12
			} else {
				severity, impact = model.SeverityInfo, 0
			}
		}
		summary = fmt.Sprintf("%s (recorded %s ago)", summary, humanDuration(age))
	}
	cmd := kernelDiagnosticCommand(event.Kind, eventTime)
	return findingWithEventTime("kernel-"+event.Kind, severity, "kernel", "Kernel event: "+event.Kind, summary, suggestion, cmd, eventTime, impact)
}

func kernelDiagnosticCommand(kind string, eventTime *time.Time) string {
	var pattern string
	switch kind {
	case "oom":
		pattern = "oom-killer"
	case "panic":
		pattern = "kernel panic"
	case "oops":
		pattern = "oops"
	case "cgroup_oom":
		pattern = "cgroup.*oom"
	case "hardware_error":
		pattern = "machine check|mce|hardware error"
	case "filesystem_corruption":
		pattern = "corrupted inode|bad block"
	case "filesystem_readonly_remount":
		pattern = "read-only|remount.*ro"
	case "disk_full":
		pattern = "no space|disk full|ENOSPC"
	case "link_up", "link_down":
		pattern = "link|carrier"
	default:
		return "journalctl -k | tail -50"
	}

	if eventTime != nil {
		// Use the date of the event to avoid hardcoded time windows
		dateStr := eventTime.Local().Format("2006-01-02")
		return fmt.Sprintf("journalctl -k --since '%s' -q | grep -A3 -B3 -Ei '%s'", dateStr, pattern)
	}
	// Fallback if no event time: use a 24-hour window
	return fmt.Sprintf("journalctl -k --since '24 hours ago' -q | grep -A3 -B3 -Ei '%s'", pattern)
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%.0fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%.0fm", d.Minutes())
	default:
		return fmt.Sprintf("%.1fh", d.Hours())
	}
}

// taskCeiling is the effective limit on live tasks: whichever of threads-max
// and pid_max is reached first.
func taskCeiling(resources *model.Resources) uint64 {
	switch {
	case resources.ThreadsMaximum == 0:
		return resources.ProcessesMaximum
	case resources.ProcessesMaximum == 0:
		return resources.ThreadsMaximum
	case resources.ThreadsMaximum < resources.ProcessesMaximum:
		return resources.ThreadsMaximum
	default:
		return resources.ProcessesMaximum
	}
}

func criticalKernelEvent(kind string) bool {
	switch kind {
	case "oom", "cgroup_oom", "hardware_error", "filesystem_corruption", "kernel_panic", "kernel_oops", "filesystem_readonly_remount", "disk_full":
		return true
	default:
		return false
	}
}

func fraction(numerator, denominator uint64) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
func finding(id string, s model.Severity, category, title, summary, suggestion string, impact int) model.Finding {
	return model.Finding{ID: id, Severity: s, Category: category, Title: title, Summary: summary, Suggestion: suggestion, ScoreImpact: impact}
}

func findingWithDiagnostic(id string, s model.Severity, category, title, summary, suggestion, diagnostic string, impact int) model.Finding {
	return model.Finding{ID: id, Severity: s, Category: category, Title: title, Summary: summary, Suggestion: suggestion, DiagnosticCommand: diagnostic, ScoreImpact: impact}
}

func findingWithEventTime(id string, s model.Severity, category, title, summary, suggestion, diagnostic string, eventTime *time.Time, impact int) model.Finding {
	return model.Finding{ID: id, Severity: s, Category: category, Title: title, Summary: summary, Suggestion: suggestion, DiagnosticCommand: diagnostic, EventTime: eventTime, ScoreImpact: impact}
}
func pressureMemory(p *model.Pressure) float64 {
	if p == nil {
		return 0
	}
	return p.Memory.SomeAvg10
}

// bytes scales so a large limit does not read as a six-digit MiB figure.
func bytes(v uint64) string {
	const unit = 1024.0
	value := float64(v)
	for _, suffix := range []string{"B", "KiB", "MiB", "GiB", "TiB"} {
		if value < unit || suffix == "TiB" {
			if suffix == "B" {
				return fmt.Sprintf("%d B", v)
			}
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
		value /= unit
	}
	return fmt.Sprintf("%.1f TiB", value)
}
func rank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 3
	case model.SeverityWarning:
		return 2
	case model.SeverityInfo:
		return 1
	}
	return 0
}
func label(score int, s model.Severity) string {
	if s == model.SeverityCritical {
		return "CRITICAL"
	}
	if score >= 90 {
		return "EXCELLENT"
	}
	if score >= 75 {
		return "GOOD"
	}
	if score >= 60 {
		return "DEGRADED"
	}
	return "POOR"
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Thresholds are collected here rather than left inline: they are the product,
// they are what HEALTH-CHECKS.md documents, and scattering them as literals is
// what let related rules drift apart.
const (
	networkMinimumEvents = 10
	networkWarningRatio  = .01

	cpuUtilizationWarning = .90
	cpuPressureWarning    = 5.0
	cpuStealWarning       = .10
	cpuStealPressure      = 5.0

	memoryAvailableWarning = .08
	memoryPressureWarning  = 1.0

	filesystemWarning = .85
	filesystemFull    = .95
	inodeWarning      = .90
	inodeFull         = .98

	// thermalMargin is how close to the sensor's own critical limit counts as
	// noteworthy. Reaching it is informational rather than a warning: a
	// modern CPU boosting to within a few degrees of Tjmax is normal, and
	// only crossing the limit the hardware itself declares is a fault.
	thermalMargin = 5.0

	resourceWarning = .90
	resourceFull    = .98

	// kernelEventRecent bounds how long a journal record is treated as a
	// current incident. Older records stay in the report, one severity lower,
	// so an overnight event does not read as urgently at noon as it did at
	// 03:00. EDAC counters are treated the same way: cumulative evidence is
	// informational, not a live fault.
	kernelEventRecent = time.Hour

	// categoryImpactCap bounds how much any one category can subtract. Without
	// it, a handful of findings in a single subsystem floors the score at zero
	// and the EXCELLENT/GOOD/DEGRADED bands stop conveying anything.
	categoryImpactCap = 30
)

// Successful empty lists are observations; unavailable capabilities are not.
func usableMetrics(m model.Metrics) bool {
	return usableCPU(m.CPU) || (m.Memory != nil && m.Memory.TotalBytes > 0) || len(m.Filesystems) > 0 || m.Network != nil || m.Disks != nil || len(m.Thermal) > 0 || m.Processes != nil || m.TCP != nil || m.Conntrack != nil || (m.Resources != nil && *m.Resources != (model.Resources{})) || len(m.DeviceHealth) > 0 || m.Containers != nil || m.ZFSPools != nil || len(m.SoftwareRAID) > 0 || m.LVM != nil || len(m.MountChecks) > 0 || (m.NetworkState != nil && m.NetworkState.Available) || (m.Hardware != nil && m.Hardware.Available) ||
		(m.Systemd != nil && m.Systemd.Available) || (m.Kernel != nil && m.Kernel.Available) || (m.TimeSync != nil && m.TimeSync.Available) || (m.CgroupV2 != nil && m.CgroupV2.Available) || (m.Security != nil && m.Security.Available)
}

func usableCPU(cpu *model.CPU) bool { return cpu != nil && (cpu.Sampled == nil || *cpu.Sampled) }

// insufficientCoverage reports whether the report lacks the observations a
// verdict needs. An interrupted run qualifies; a boundary that ran out of its
// own budget does not, because the collectors that finished are still valid.
func insufficientCoverage(r *model.Report) bool {
	for _, status := range r.Collection {
		if status.Collector == "sampling" && status.Status == "error" {
			return true
		}
	}
	if !usableMetrics(r.Metrics) {
		return true
	}
	// When a core collector was registered, all three of its peers producing
	// nothing means there is no host-level observation to reason from.
	if !coreCollectorPresent(r.Collection) {
		return false
	}
	return !usableCPU(r.Metrics.CPU) &&
		(r.Metrics.Memory == nil || r.Metrics.Memory.TotalBytes == 0) &&
		len(r.Metrics.Filesystems) == 0
}

func coreCollectorPresent(statuses []model.CollectionStatus) bool {
	for _, status := range statuses {
		switch status.Collector {
		case "cpu", "memory", "filesystems":
			return true
		}
	}
	return false
}
