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
		findings = append(findings, finding("cpu-contention", model.SeverityWarning, "cpu", "Sustained CPU contention", fmt.Sprintf("CPU averaged %.0f%%, load was %.1f across %d CPUs, and CPU PSI some avg10 was %.1f%%.", cpu.Utilization*100, cpu.Load1, report.Host.CPUCount, m.Pressure.CPU.SomeAvg10), "Inspect runnable processes and CPU limits.", 10))
	}
	if cpu := m.CPU; cpu != nil && (cpu.Sampled == nil || *cpu.Sampled) && cpu.Steal >= cpuStealWarning && m.Pressure != nil && m.Pressure.CPU.SomeAvg10 >= cpuStealPressure {
		findings = append(findings, finding("cpu-steal", model.SeverityWarning, "cpu", "CPU time lost to the hypervisor", fmt.Sprintf("Steal averaged %.1f%% during the sample and CPU PSI some avg10 was %.1f%%.", cpu.Steal*100, m.Pressure.CPU.SomeAvg10), "Inspect hypervisor contention and the VM CPU allocation.", 10))
	}

	if mem := m.Memory; mem != nil && mem.AvailableFraction < memoryAvailableWarning && ((m.Pressure != nil && m.Pressure.Memory.SomeAvg10 >= memoryPressureWarning) || mem.SwapInBytes > 0 || mem.SwapOutBytes > 0) {
		findings = append(findings, finding("memory-pressure", model.SeverityWarning, "memory", "Memory pressure observed", fmt.Sprintf("MemAvailable is %.1f%%; memory PSI some avg10 is %.1f%%; swap activity during the sample was %s.", mem.AvailableFraction*100, pressureMemory(m.Pressure), bytes(mem.SwapInBytes+mem.SwapOutBytes)), "Inspect top memory consumers and cgroup limits.", 12))
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
			findings = append(findings, finding("filesystem-"+fs.MountPoint, model.SeverityCritical, "filesystem", "Filesystem nearly full", fmt.Sprintf("%s (%s) is %.1f%% used.", fs.MountPoint, fs.Type, fs.UsedFraction*100), "Free space or review retention policies.", 20))
		} else if fs.UsedFraction >= filesystemWarning {
			findings = append(findings, finding("filesystem-"+fs.MountPoint, model.SeverityWarning, "filesystem", "Filesystem filling up", fmt.Sprintf("%s (%s) is %.1f%% used.", fs.MountPoint, fs.Type, fs.UsedFraction*100), "Review large files and retention policies.", 8))
		}
		if fs.InodesTotal > 0 && fs.InodesFree <= fs.InodesTotal {
			used := fraction(fs.InodesTotal-fs.InodesFree, fs.InodesTotal)
			if used >= inodeWarning {
				severity, impact := model.SeverityWarning, 8
				if used >= inodeFull {
					severity, impact = model.SeverityCritical, 20
				}
				findings = append(findings, finding("filesystem-inodes-"+fs.MountPoint, severity, "filesystem", "Filesystem inode capacity nearly exhausted", fmt.Sprintf("%s has %d of %d inodes free (%.1f%% used).", fs.MountPoint, fs.InodesFree, fs.InodesTotal, used*100), "Inspect directories with many small files and their retention policies.", impact))
			}
		}
	}
	for _, n := range m.Network {
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
				findings = append(findings, finding("network-"+n.Name+"-"+direction.name+"-"+signal.name, model.SeverityWarning, "network", "Elevated network "+signal.name, fmt.Sprintf("%s %s recorded %d %s alongside %d packets during the sample (%.1f%%).", n.Name, direction.name, signal.count, signal.name, direction.packets, ratio*100), "Inspect interface and peer counters; for drops and overruns, also inspect queues and application receive capacity.", 7))
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
			findings = append(findings, finding("thermal-"+t.Name, model.SeverityWarning, "thermal", "Temperature at or above critical limit", fmt.Sprintf("%s is %.1f°C (critical %.1f°C).", t.Name, t.TemperatureC, t.CriticalC), "Check cooling, airflow, and load; sustained operation at this temperature will throttle or damage hardware.", 10))
		case t.TemperatureC >= t.CriticalC-thermalMargin:
			findings = append(findings, finding("thermal-"+t.Name, model.SeverityInfo, "thermal", "Temperature approaching critical limit", fmt.Sprintf("%s is %.1f°C, within %.0f°C of its %.1f°C critical limit.", t.Name, t.TemperatureC, thermalMargin, t.CriticalC), "Expected under sustained load on many CPUs; check cooling and airflow if it persists at idle.", 0))
		}
	}
	if p := m.Processes; p != nil && p.Zombies > 0 {
		summary, suggestion := zombieDetails(p)
		findings = append(findings, finding("zombies", model.SeverityInfo, "process", zombieTitle(p), summary, suggestion, 0))
	}
	if p := m.Processes; p != nil && len(p.StuckProcesses) > 0 {
		findings = append(findings, stuckProcessFinding(p))
	}
	if s := m.Systemd; s != nil && len(s.FailedUnits) > 0 {
		findings = append(findings, finding("failed-units", model.SeverityCritical, "services", "Failed systemd units", fmt.Sprintf("%d failed units: %v", len(s.FailedUnits), s.FailedUnits), "Run systemctl --failed and inspect the affected unit logs.", 25))
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
			findings = append(findings, finding("systemd-restarting-"+u.Unit, severity, "services", fmt.Sprintf("Systemd unit %s is restarting repeatedly", u.Unit),
				fmt.Sprintf("%s restarted %d time(s) during the sampling window. A unit does not normally restart while being observed; this can mean the service is crash-looping even though it may show as active between restarts.", u.Unit, u.RestartsDelta),
				fmt.Sprintf("Inspect recent logs (journalctl -u %s) and the unit's exit status.", u.Unit), impact))
		}
	}
	if k := m.Kernel; k != nil {
		for _, event := range k.Events {
			findings = append(findings, kernelFinding(event))
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
	if insufficientCoverage(report) && !hasHealthFailure(findings) {
		report.Score = model.Score{Value: 0, Status: model.SeverityUnknown, Label: "INSUFFICIENT DATA"}
		return
	}
	report.Score = scoreFindings(findings)
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

// stuckProcessFinding reports processes the kernel had in uninterruptible
// sleep (D state) for the entire sampling window -- a process cannot be
// killed out of D state, and its parent's load contribution keeps rising
// for as long as it stays there. A brief, one-boundary D state is normal and
// not reported at all (see stuckInD); this only fires once a process has
// already been stuck the whole time this report was watching.
func stuckProcessFinding(processes *model.Processes) model.Finding {
	items := make([]string, 0, len(processes.StuckProcesses))
	for _, process := range processes.StuckProcesses {
		item := fmt.Sprintf("PID %d (%s)", process.PID, process.Command)
		if process.ParentPID > 0 {
			item += fmt.Sprintf(", parent PID %d", process.ParentPID)
		}
		items = append(items, item)
	}
	severity, impact := model.SeverityWarning, 10
	if len(processes.StuckProcesses) >= 3 {
		severity, impact = model.SeverityCritical, 18
	}
	return finding("process-stuck-uninterruptible", severity, "process", "Process stuck in uninterruptible sleep (D state)",
		fmt.Sprintf("%d process(es) stayed in D state for the entire sampling window: %s. A process in this state is waiting on the kernel (usually disk or NFS I/O) and cannot be killed until that wait resolves.", len(processes.StuckProcesses), strings.Join(items, "; ")),
		"Inspect the underlying storage or NFS mount for the affected process; if it never clears, the backing device or server is the more likely fault than the process itself.", impact)
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

func cgroupFindings(cgroup *model.CgroupV2, pressure *model.Pressure) []model.Finding {
	if cgroup == nil || !cgroup.Available {
		return nil
	}
	var findings []model.Finding
	if cgroup.MemoryOOMKillDelta > 0 {
		findings = append(findings, finding("cgroup-oom-kill", model.SeverityCritical, "cgroup", "Cgroup OOM kills during sample", fmt.Sprintf("The current cgroup recorded %d OOM kill(s) during the sampling window.", cgroup.MemoryOOMKillDelta), "Inspect the workload's memory limit and the largest memory consumers.", 25))
	} else if cgroup.MemoryOOMDelta > 0 {
		findings = append(findings, finding("cgroup-oom", model.SeverityWarning, "cgroup", "Cgroup memory allocation failures", fmt.Sprintf("The current cgroup recorded %d memory OOM event(s) during the sampling window.", cgroup.MemoryOOMDelta), "Inspect the workload's memory limit and memory demand.", 15))
	}
	if cgroup.CPUUsageSecondsDelta >= .1 && cgroup.CPUThrottledSecondsDelta >= .1 && cgroup.CPUThrottledSecondsDelta/cgroup.CPUUsageSecondsDelta >= .10 {
		findings = append(findings, finding("cgroup-cpu-throttling", model.SeverityWarning, "cgroup", "Cgroup CPU quota throttling", fmt.Sprintf("The current cgroup spent %.1fs throttled while using %.1fs CPU during the sample.", cgroup.CPUThrottledSecondsDelta, cgroup.CPUUsageSecondsDelta), "Inspect the CPU quota and runnable workload in this cgroup.", 10))
	}
	if cgroup.PIDsMax != nil && *cgroup.PIDsMax > 0 && fraction(cgroup.PIDsCurrent, *cgroup.PIDsMax) >= .95 {
		findings = append(findings, finding("cgroup-pids-limit", model.SeverityWarning, "cgroup", "Cgroup PID limit nearly exhausted", fmt.Sprintf("The current cgroup uses %d of %d allowed PIDs.", cgroup.PIDsCurrent, *cgroup.PIDsMax), "Inspect process growth and raise the cgroup PID limit only if demand is expected.", 10))
	}
	if cgroup.Containerized && cgroup.MemoryMaxBytes != nil && *cgroup.MemoryMaxBytes > 0 && fraction(cgroup.MemoryCurrentBytes, *cgroup.MemoryMaxBytes) >= .95 && (cgroup.MemoryOOMDelta > 0 || cgroup.MemoryOOMKillDelta > 0 || pressure != nil && pressure.Memory.SomeAvg10 >= 1) {
		findings = append(findings, finding("cgroup-memory-limit", model.SeverityWarning, "cgroup", "Container memory limit under pressure", fmt.Sprintf("The current cgroup uses %.1f%% of its %s memory limit with corroborating memory pressure.", fraction(cgroup.MemoryCurrentBytes, *cgroup.MemoryMaxBytes)*100, bytes(*cgroup.MemoryMaxBytes)), "Inspect the container memory limit and workload memory demand.", 12))
	}
	return findings
}

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
				findings = append(findings, finding(prefix+"-oom", model.SeverityCritical, "containers", "Container was OOM-killed", fmt.Sprintf("%s container %s reports an OOM-killed state.", runtime.Runtime, name), "Inspect its memory limit, recent logs, and workload memory demand.", 20))
			}
			if container.Healthy != nil && !*container.Healthy {
				findings = append(findings, finding(prefix+"-unhealthy", model.SeverityWarning, "containers", "Container health check is failing", fmt.Sprintf("%s container %s is marked unhealthy.", runtime.Runtime, name), "Inspect the container health check and recent application logs.", 12))
			}
			if container.RestartCount > 0 {
				severity, impact := model.SeverityWarning, 12
				if container.RestartCount >= 3 {
					severity, impact = model.SeverityCritical, 20
				}
				findings = append(findings, finding(prefix+"-restarts", severity, "containers", "Container restarted during sample", fmt.Sprintf("%s container %s restarted %d time(s) during the sampling window.", runtime.Runtime, name, container.RestartCount), "Inspect exit status and recent application logs.", impact))
			}
			if strings.EqualFold(container.State, "exited") && container.HasRestartPolicy {
				findings = append(findings, finding(prefix+"-exited", model.SeverityWarning, "containers", "Restart-managed container is exited", fmt.Sprintf("%s container %s is exited despite a restart policy.", runtime.Runtime, name), "Inspect exit status, runtime events, and the restart policy.", 10))
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
				findings = append(findings, model.Finding{
					ID:          prefix + "-log-events",
					Severity:    model.SeverityWarning,
					Category:    "containers",
					Title:       "Container log reports a failure",
					Summary:     fmt.Sprintf("%s container %s logged %s in the last hour.", runtime.Runtime, name, describeLogKinds(specific)),
					Evidence:    logEvidence(specific),
					Suggestion:  fmt.Sprintf("Review with %s logs --since 1h %s", runtime.Runtime, name),
					ScoreImpact: 8,
				})
			} else if len(generic) > 0 {
				findings = append(findings, model.Finding{
					ID:          prefix + "-log-messages",
					Severity:    model.SeverityInfo,
					Category:    "containers",
					Title:       fmt.Sprintf("Container %s logged %d error/failure line(s)", name, len(generic)),
					Summary:     fmt.Sprintf("%s container %s logged lines matching generic error wording; this is context, not a detected fault.", runtime.Runtime, name),
					Evidence:    logEvidence(generic),
					Suggestion:  fmt.Sprintf("Review with %s logs --since 1h %s", runtime.Runtime, name),
					ScoreImpact: 0,
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
			findings = append(findings, finding("zfs-pool-"+pool.Name+"-scan", model.SeverityInfo, "zfs", "ZFS maintenance scan is running", fmt.Sprintf("Pool %s: %s", pool.Name, pool.ScanState), "Monitor zpool status for completion; temporary extra disk activity is expected.", 0))
		}
		if pool.Health != "" && !strings.EqualFold(pool.Health, "ONLINE") {
			findings = append(findings, finding("zfs-pool-"+pool.Name+"-health", model.SeverityCritical, "zfs", "ZFS pool is not ONLINE", fmt.Sprintf("Pool %s reports health %s.", pool.Name, pool.Health), "Run zpool status -v and repair or replace affected devices before relying on the pool.", 30))
			continue
		}
		if pool.PermanentErrors {
			findings = append(findings, finding("zfs-pool-"+pool.Name+"-permanent-errors", model.SeverityCritical, "zfs", "ZFS reports permanent data errors", fmt.Sprintf("Pool %s is ONLINE but zpool status reports permanent data errors.", pool.Name), "Restore affected data from backup and investigate zpool status -v immediately.", 30))
			continue
		}
		if pool.ReadErrors+pool.WriteErrors+pool.ChecksumErrors > 0 {
			findings = append(findings, finding("zfs-pool-"+pool.Name+"-io-errors", model.SeverityWarning, "zfs", "ZFS pool reports device errors", fmt.Sprintf("Pool %s has %d read, %d write, and %d checksum errors.", pool.Name, pool.ReadErrors, pool.WriteErrors, pool.ChecksumErrors), "Run zpool status -v and inspect the affected device path and cables.", 15))
		}
	}
	return findings
}

func diskFindings(report *model.Report) []model.Finding {
	var findings []model.Finding
	for _, disk := range report.Metrics.Disks {
		// Throughput alone is not a failure. Require saturation and a latency or
		// queueing symptom, plus independent host pressure before warning.
		queued := disk.AverageQueueDepth >= 2 || disk.AverageLatencyMillis >= 50
		pressure := report.Metrics.Pressure != nil && report.Metrics.Pressure.IO.SomeAvg10 >= 1
		iowait := report.Metrics.CPU != nil && report.Metrics.CPU.IOWait >= .10
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
		findings = append(findings, finding("disk-contention-"+disk.Name, severity, "disk", "Storage I/O contention", fmt.Sprintf("%s was %.0f%% busy with an average queue depth of %.1f and %.1f ms average I/O latency; additional evidence: %s.", disk.Name, disk.Utilization*100, disk.AverageQueueDepth, disk.AverageLatencyMillis, corroboration), "Inspect the busiest processes, device latency, and underlying storage path.", impact))
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
		findings = append(findings, finding("network-"+n.Name+"-link-errors", model.SeverityWarning, "network", "Physical link errors",
			fmt.Sprintf("%s recorded %d frame errors and %d carrier losses during the sample.", n.Name, n.RXFrameErrors, n.TXCarrierErrors),
			"Inspect the cable, the transceiver or SFP, and the counters on the switch port.", 8))
	}
	// Collisions are normal on a half-duplex segment and carry no fault there.
	// On a link the driver reports as full duplex they are the classic symptom
	// of a duplex mismatch with the switch port.
	if n.Collisions >= networkMinimumEvents && strings.EqualFold(strings.TrimSpace(n.Duplex), "full") {
		findings = append(findings, finding("network-"+n.Name+"-collisions", model.SeverityWarning, "network", "Collisions on a full-duplex link",
			fmt.Sprintf("%s negotiated full duplex but recorded %d collisions during the sample.", n.Name, n.Collisions),
			"Compare the duplex setting on this interface with the switch port; a mismatch is the usual cause.", 8))
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
	return []model.Finding{finding("conntrack-drops", model.SeverityWarning, "network", "Connection tracking dropped packets",
		fmt.Sprintf("Netfilter recorded %d drops, %d early drops, and %d failed inserts during the sample.", conntrack.Drops, conntrack.EarlyDrops, conntrack.InsertFailed),
		"Inspect the connection rate against nf_conntrack_max and the conntrack timeouts for the busiest protocol.", 12)}
}

func tcpFindings(tcp *model.TCP, resources *model.Resources, ipv6 *model.IPv6Check) []model.Finding {
	if tcp == nil {
		return nil
	}
	var findings []model.Finding
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
		findings = append(findings, finding("tcp-retransmits", severity, "network", "Elevated TCP retransmissions", summary, suggestion, impact))
	}
	if tcp.ListenOverflows+tcp.ListenDrops > 0 {
		// Naming somaxconn turns the finding from an observation into a number
		// the reader can act on, since it is the ceiling every listener's
		// requested backlog is silently capped to.
		ceiling := ""
		if resources != nil && resources.ListenBacklogMaximum > 0 {
			ceiling = fmt.Sprintf(" net.core.somaxconn is %d.", resources.ListenBacklogMaximum)
		}
		findings = append(findings, finding("tcp-listen-overflow", model.SeverityWarning, "network", "TCP listen queue overflow", fmt.Sprintf("The kernel recorded %d listen overflows or drops during the sample.%s", tcp.ListenOverflows+tcp.ListenDrops, ceiling), "Inspect the affected listener's backlog, accept rate, and file descriptor limits.", 12))
	}
	if opens := tcp.ActiveOpens + tcp.PassiveOpens; opens >= 50 && fraction(tcp.AttemptFails, opens) >= .10 {
		findings = append(findings, finding("tcp-connect-failures", model.SeverityWarning, "network", "Elevated TCP connection failures", fmt.Sprintf("%d of %d TCP connection attempts failed during the sample.", tcp.AttemptFails, opens), "Inspect destination availability, DNS, firewall rules, and application logs.", 8))
	}
	// Socket tables have explicit kernel ceilings, which is what makes a
	// "large" socket count judgeable at all. An absolute threshold without one
	// would fire on every busy host.
	if resources != nil {
		for _, limit := range []struct {
			id, title, advice string
			current, maximum  uint64
		}{
			{"tcp-time-wait-saturation", "TIME_WAIT table nearly exhausted", "Inspect connection churn and whether clients reuse connections; the kernel discards the oldest entries once the bucket is full.", tcp.TimeWaitSockets, resources.TimeWaitMaximum},
			{"tcp-orphan-saturation", "Orphaned socket table nearly exhausted", "Inspect applications abandoning sockets with unsent data; the kernel resets orphans once the limit is reached.", tcp.OrphanSockets, resources.OrphanMaximum},
		} {
			if limit.maximum == 0 || fraction(limit.current, limit.maximum) < resourceWarning {
				continue
			}
			findings = append(findings, finding(limit.id, model.SeverityWarning, "network", limit.title,
				fmt.Sprintf("%d of %d entries are in use (%.0f%%).", limit.current, limit.maximum, fraction(limit.current, limit.maximum)*100),
				limit.advice, 10))
		}
	}
	return findings
}

func deviceHealthFindings(devices []model.DeviceHealth) []model.Finding {
	var findings []model.Finding
	for _, device := range devices {
		if device.OverallPassed != nil && !*device.OverallPassed || device.CriticalWarning != 0 || device.PendingSectors != 0 || device.Uncorrectable != 0 || device.MediaErrors != 0 {
			findings = append(findings, finding("device-health-"+device.Device, model.SeverityCritical, "disk", "Device health requires attention", fmt.Sprintf("%s reported a SMART/NVMe health failure or uncorrectable media error.", device.Device), "Back up important data and inspect the device's SMART/NVMe log promptly.", 25))
			continue
		}
		if device.AvailableSpare > 0 && device.AvailableSpare < .10 || device.PercentageUsed >= .95 {
			findings = append(findings, finding("device-wear-"+device.Device, model.SeverityWarning, "disk", "Device endurance is nearly exhausted", fmt.Sprintf("%s reports %.0f%% spare remaining and %.0f%% endurance used.", device.Device, device.AvailableSpare*100, device.PercentageUsed*100), "Plan replacement and verify current backups.", 14))
		}
	}
	return findings
}

func timeSyncFindings(sync *model.TimeSync) []model.Finding {
	if sync == nil || !sync.Available {
		return nil
	}
	if sync.Synchronized != nil && !*sync.Synchronized {
		return []model.Finding{finding("time-unsynchronized", model.SeverityWarning, "time", "System clock is not synchronized", fmt.Sprintf("%s reports that the system clock is unsynchronized.", sync.Service), "Inspect the time synchronization service, sources, and network reachability.", 10)}
	}
	if sync.OffsetMillis != nil && abs(*sync.OffsetMillis) >= 1000 {
		severity, impact := model.SeverityWarning, 8
		if abs(*sync.OffsetMillis) >= 5000 {
			severity, impact = model.SeverityCritical, 16
		}
		return []model.Finding{finding("time-offset", severity, "time", "Large clock offset", fmt.Sprintf("%s reports an offset of %.0f ms.", sync.Service, *sync.OffsetMillis), "Inspect time sources and correct clock synchronization before relying on timestamps.", impact)}
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
		id, title        string
		current, maximum uint64
	}{
		{"file-descriptors", "File descriptor capacity nearly exhausted", resources.OpenFiles, resources.OpenFilesMaximum},
		{"tasks", "Process and thread capacity nearly exhausted", resources.Processes, taskCeiling(resources)},
		{"conntrack", "Conntrack table nearly exhausted", resources.Conntrack, resources.ConntrackMaximum},
	} {
		if limit.maximum == 0 || fraction(limit.current, limit.maximum) < resourceWarning {
			continue
		}
		severity, impact := model.SeverityWarning, 12
		if fraction(limit.current, limit.maximum) >= resourceFull {
			severity, impact = model.SeverityCritical, 20
		}
		findings = append(findings, finding("resource-"+limit.id, severity, "resources", limit.title, fmt.Sprintf("%d of %d (%0.f%%) are currently in use.", limit.current, limit.maximum, fraction(limit.current, limit.maximum)*100), "Identify consumers and raise the limit only after confirming expected demand.", impact))
	}
	return findings
}

// kernelFinding weighs a journal record by kind and by age. The journal scan
// covers the current boot up to 24 hours, so without an age an incident from
// overnight reads exactly as urgently as one happening now.
func kernelFinding(event model.LogEvent) model.Finding {
	severity, impact := model.SeverityWarning, 12
	if criticalKernelEvent(event.Kind) {
		severity, impact = model.SeverityCritical, 25
	}
	summary := event.Message
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
	return finding("kernel-"+event.Kind, severity, "kernel", "Kernel event: "+event.Kind, summary, "Inspect the kernel journal and affected hardware or workload.", impact)
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
	case "oom", "cgroup_oom", "hardware_error", "filesystem_corruption", "kernel_panic", "kernel_oops":
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
func hasHealthFailure(findings []model.Finding) bool {
	for _, f := range findings {
		if rank(f.Severity) >= rank(model.SeverityWarning) {
			return true
		}
	}
	return false
}

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
