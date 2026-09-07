// Package render provides a compact non-interactive terminal report.
package render

import (
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/elcool0r/glimpse/internal/model"
)

type Options struct {
	Color bool
	// Verbose includes process rankings, per-item inventories, and collection
	// diagnostics attached to the row each check belongs to. The default
	// report is limited to the health overview.
	Verbose bool
	// Width is the usable terminal width. A zero value uses a conservative
	// 80-column layout, which is also safe for redirected output.
	Width int
	// ASCII avoids Unicode separators and sparklines for limited terminals.
	ASCII bool
	// Quiet suppresses rows and detail lines that are fully healthy (a
	// section badge of OK), leaving only rows with something to say:
	// INFO, WARN, CRIT, or UNKNOWN.
	Quiet bool
	// Events always shows the "Recent events" timeline. Without it, the
	// timeline only appears when the report already has a critical finding,
	// since it exists to give a critical its story, not to narrate a
	// healthy run.
	Events bool
	// EventsAll shows every timeline event instead of capping it at
	// maxTimelineEvents. It implies Events.
	EventsAll bool
}

func Write(w io.Writer, r model.Report, o Options) {
	width := o.Width
	if width <= 0 {
		width = 80
	}
	if width < 40 {
		width = 40
	}
	separator := " · "
	if o.ASCII {
		separator = " | "
	}
	bold := func(s string) string {
		if o.Color {
			return "\x1b[1m" + s + "\x1b[0m"
		}
		return s
	}
	metricSeverity := func(name string, severity model.Severity, text string) string {
		return fmt.Sprintf("%s %s  %s", sectionLabel(name, severity, o.Color), badge(severity, o.Color), text)
	}
	note := func(collector string) {
		if o.Verbose {
			writeCollectionNote(w, width, r, collector, o.Color)
		}
	}
	quietSkip := func(severity model.Severity) bool {
		return o.Quiet && severity == model.SeverityOK
	}
	writeWrapped(w, width, "", fmt.Sprintf("%s  %s", bold("GLIMPSE"), cleanText(r.Host.Hostname)))
	writeWrapped(w, width, "", metadata(strings.Join(nonEmpty(r.Host.OS, r.Host.Kernel, fmt.Sprintf("%d CPUs", r.Host.CPUCount), fmt.Sprintf("sampled %.0fs", r.SampleDurationSeconds)), separator), o.Color))
	fmt.Fprintln(w)
	if c := r.Metrics.CPU; c != nil {
		severity := sectionSeverity(r.Findings, "cpu")
		if !quietSkip(severity) {
			writeWrapped(w, width, "", metricSeverity("CPU", severity, fmt.Sprintf("%s%sload %.2f%sI/O wait %.1f%%", cpuUtilization(c), separator, c.Load1, separator, c.IOWait*100)))
			note("cpu")
		}
	}
	if m := r.Metrics.Memory; m != nil {
		severity := sectionSeverity(r.Findings, "memory")
		if !quietSkip(severity) {
			writeWrapped(w, width, "", metricSeverity("Memory", severity, fmt.Sprintf("%.1f%% available (%s / %s)%sswap %s / %s used", m.AvailableFraction*100, size(m.AvailableBytes), size(m.TotalBytes), separator, size(swapUsed(m)), size(m.SwapTotalBytes))))
			note("memory")
		}
	}
	if len(r.Metrics.Filesystems) > 0 {
		// Read-only image mounts are full by construction, so reporting one as
		// the fullest filesystem says nothing about the host's capacity.
		fullest := fullestWritable(r.Metrics.Filesystems)
		severity := sectionSeverity(r.Findings, "filesystem")
		if !quietSkip(severity) {
			writeWrapped(w, width, "", metricSeverity("Storage", severity, fmt.Sprintf("%d mounted%s%s %.1f%% used%s%s available", len(r.Metrics.Filesystems), separator, cleanText(fullest.MountPoint), fullest.UsedFraction*100, separator, size(fullest.AvailableBytes))))
			if o.Verbose {
				for _, fs := range r.Metrics.Filesystems {
					fsSeverity := findingSeverity(r.Findings, "filesystem-"+fs.MountPoint, "filesystem-inodes-"+fs.MountPoint, "filesystem-read-only-"+fs.MountPoint)
					detail := fmt.Sprintf("%s%s%.1f%% used%s%s available", cleanText(fs.Type), separator, fs.UsedFraction*100, separator, size(fs.AvailableBytes))
					if fs.ReadOnly {
						detail += separator + "read-only"
					}
					checkLine(w, width, "    ", cleanText(fs.MountPoint), fsSeverity, o.Color, detail)
				}
			}
			note("filesystems")
		}
	}
	if len(r.Metrics.Disks) > 0 {
		busiest := busiestDisk(r.Metrics.Disks)
		duration := busiest.SampleDurationSeconds
		if duration <= 0 {
			duration = r.SampleDurationSeconds
		}
		severity := sectionSeverity(r.Findings, "disk")
		if !quietSkip(severity) {
			writeWrapped(w, width, "", metricSeverity("Disk", severity, fmt.Sprintf("%d %s%s%s %.0f%% busy%s%s/s", len(r.Metrics.Disks), diskKind(r.Metrics.Disks), separator, cleanText(busiest.Name), busiest.Utilization*100, separator, sizePerSecond(busiest.ReadBytes+busiest.WriteBytes, duration))))
			if o.Verbose {
				for _, disk := range r.Metrics.Disks {
					diskDuration := disk.SampleDurationSeconds
					if diskDuration <= 0 {
						diskDuration = r.SampleDurationSeconds
					}
					diskSeverity := findingSeverity(r.Findings, "disk-contention-"+disk.Name)
					detail := fmt.Sprintf("%.0f%% busy%s%s/s", disk.Utilization*100, separator, sizePerSecond(disk.ReadBytes+disk.WriteBytes, diskDuration))
					checkLine(w, width, "    ", cleanText(disk.Name), diskSeverity, o.Color, detail)
				}
			}
			note("disk")
		}
	}
	if len(r.Metrics.Network) > 0 {
		busiest := busiestNetwork(r.Metrics.Network)
		duration := busiest.SampleDurationSeconds
		if duration <= 0 {
			duration = r.SampleDurationSeconds
		}
		netSeverity := maxSeverity(findingSeverityByPrefix(r.Findings, "network", "network-"), findingSeverity(r.Findings, "conntrack-drops"))
		if !quietSkip(netSeverity) {
			writeWrapped(w, width, "", metricSeverity("Network", netSeverity, fmt.Sprintf("%d interfaces%s%s%s RX %s/s%sTX %s/s", len(r.Metrics.Network), separator, cleanText(busiest.Name), linkSummary(busiest), sizePerSecond(busiest.RXBytes, duration), separator, sizePerSecond(busiest.TXBytes, duration))))
			if o.Verbose {
				for _, iface := range r.Metrics.Network {
					ifaceDuration := iface.SampleDurationSeconds
					if ifaceDuration <= 0 {
						ifaceDuration = r.SampleDurationSeconds
					}
					severity := findingSeverityByPrefix(r.Findings, "network", "network-"+iface.Name+"-")
					detail := fmt.Sprintf("RX %s/s%sTX %s/s%s", sizePerSecond(iface.RXBytes, ifaceDuration), separator, sizePerSecond(iface.TXBytes, ifaceDuration), linkSummary(iface))
					checkLine(w, width, "    ", cleanText(iface.Name), severity, o.Color, strings.TrimSuffix(detail, " "))
				}
			}
			note("network")
		}
	}
	if len(r.Metrics.Thermal) > 0 {
		unit := "°C"
		if o.ASCII {
			unit = "C"
		}
		sensor := hottestSensor(r.Metrics.Thermal)
		severity := sectionSeverity(r.Findings, "thermal")
		if !quietSkip(severity) {
			writeWrapped(w, width, "", metricSeverity("Thermal", severity, fmt.Sprintf("%.1f%s maximum reported temperature (%s)", sensor.TemperatureC, unit, thermalLabel(sensor.Name))))
			note("thermal")
		}
	}
	if s := r.Metrics.Systemd; s != nil && s.Available {
		severity := sectionSeverity(r.Findings, "services")
		if !quietSkip(severity) {
			writeWrapped(w, width, "", metricSeverity("Services", severity, fmt.Sprintf("%d failed units", len(s.FailedUnits))))
			if o.Verbose {
				for _, unit := range s.FailedUnits {
					checkLine(w, width, "    ", cleanText(unit), model.SeverityCritical, o.Color, "failed")
				}
				for _, unit := range s.RestartingUnits {
					unitSeverity := findingSeverity(r.Findings, "systemd-restarting-"+unit.Unit)
					checkLine(w, width, "    ", cleanText(unit.Unit), unitSeverity, o.Color, fmt.Sprintf("restarted %d time(s) during the sample", unit.RestartsDelta))
				}
			} else if len(s.RestartingUnits) > 0 {
				worst := s.RestartingUnits[0]
				checkLine(w, width, "    ", "Restart loop", findingSeverity(r.Findings, "systemd-restarting-"+worst.Unit), o.Color, fmt.Sprintf("%s restarted %d time(s)", cleanText(worst.Unit), worst.RestartsDelta))
			}
			note("systemd")
		}
	}
	if tcp := r.Metrics.TCP; tcp != nil {
		tcpSeverity := findingSeverityByPrefix(r.Findings, "network", "tcp-")
		if !quietSkip(tcpSeverity) {
			writeWrapped(w, width, "", metricSeverity("TCP", tcpSeverity, fmt.Sprintf("%d retransmits / %d outbound%s%d listen drops", tcp.RetransmittedSegments, tcp.SegmentsOut, separator, tcp.ListenOverflows+tcp.ListenDrops)))
			if o.Verbose {
				checkLine(w, width, "    ", "Retransmits", findingSeverity(r.Findings, "tcp-retransmits"), o.Color, fmt.Sprintf("%d of %d outbound", tcp.RetransmittedSegments, tcp.SegmentsOut))
				checkLine(w, width, "    ", "Listen queue", findingSeverity(r.Findings, "tcp-listen-overflow"), o.Color, fmt.Sprintf("%d overflow%s%d drops", tcp.ListenOverflows, separator, tcp.ListenDrops))
				checkLine(w, width, "    ", "Connection attempts", findingSeverity(r.Findings, "tcp-connect-failures"), o.Color, fmt.Sprintf("%d of %d failed", tcp.AttemptFails, tcp.ActiveOpens+tcp.PassiveOpens))
				udpSeverity := model.SeverityOK
				if tcp.UDPInErrors > 0 {
					udpSeverity = model.SeverityInfo
				}
				checkLine(w, width, "    ", "UDP errors", udpSeverity, o.Color, fmt.Sprintf("%d", tcp.UDPInErrors))
				ipSeverity := model.SeverityOK
				if tcp.IPReassemblyFailures > 0 || tcp.IPFragmentationFailures > 0 {
					ipSeverity = model.SeverityInfo
				}
				checkLine(w, width, "    ", "IP reassembly/fragmentation", ipSeverity, o.Color, fmt.Sprintf("reassembly %d%sfragmentation %d", tcp.IPReassemblyFailures, separator, tcp.IPFragmentationFailures))
				if resources := r.Metrics.Resources; resources != nil {
					if resources.TimeWaitMaximum > 0 {
						checkLine(w, width, "    ", "TIME_WAIT table", findingSeverity(r.Findings, "tcp-time-wait-saturation"), o.Color, fmt.Sprintf("%d/%d", tcp.TimeWaitSockets, resources.TimeWaitMaximum))
					}
					if resources.OrphanMaximum > 0 {
						checkLine(w, width, "    ", "Orphan sockets", findingSeverity(r.Findings, "tcp-orphan-saturation"), o.Color, fmt.Sprintf("%d/%d", tcp.OrphanSockets, resources.OrphanMaximum))
					}
				}
			}
			note("tcp")
		}
	}
	if sync := r.Metrics.TimeSync; sync != nil && sync.Available {
		severity := sectionSeverity(r.Findings, "time")
		if !quietSkip(severity) {
			writeWrapped(w, width, "", metricSeverity("Time", severity, timeSyncStatus(sync)))
			note("time-sync")
		}
	}
	if resources := r.Metrics.Resources; resources != nil {
		if text := resourceSummary(resources); text != "" {
			severity := sectionSeverity(r.Findings, "resources")
			if !quietSkip(severity) {
				writeWrapped(w, width, "", metricSeverity("Limits", severity, text))
				if o.Verbose {
					for _, limit := range []struct {
						id, label    string
						current, max uint64
					}{
						{"resource-file-descriptors", "File descriptors", resources.OpenFiles, resources.OpenFilesMaximum},
						{"resource-tasks", "Tasks", resources.Processes, taskCeiling(resources)},
						{"resource-conntrack", "Conntrack", resources.Conntrack, resources.ConntrackMaximum},
					} {
						if limit.max == 0 {
							continue
						}
						checkLine(w, width, "    ", limit.label, findingSeverity(r.Findings, limit.id), o.Color, fmt.Sprintf("%d/%d (%.0f%%)", limit.current, limit.max, float64(limit.current)*100/float64(limit.max)))
					}
				}
				note("resources")
			}
		}
	}
	if p := r.Metrics.Processes; p != nil {
		processSeverity := sectionSeverity(r.Findings, "process")
		// A CPU or memory finding names no culprit by itself; showing the
		// ranked process lists here is what turns "CPU contention" into
		// "CPU contention, and this is probably why" without waiting for
		// --verbose.
		cpuSeverity := sectionSeverity(r.Findings, "cpu")
		memSeverity := sectionSeverity(r.Findings, "memory")
		if (o.Verbose && !o.Quiet) || severityRank(processSeverity) >= severityRank(model.SeverityWarning) || severityRank(cpuSeverity) >= severityRank(model.SeverityWarning) {
			topCPUSeverity := processSeverity
			if severityRank(cpuSeverity) > severityRank(topCPUSeverity) {
				topCPUSeverity = cpuSeverity
			}
			renderProcesses(w, width, sectionLabel("Top CPU", topCPUSeverity, o.Color), p.TopCPU, separator, p.CPUSampled)
		}
		if (o.Verbose && !o.Quiet) || severityRank(processSeverity) >= severityRank(model.SeverityWarning) || severityRank(memSeverity) >= severityRank(model.SeverityWarning) {
			topRAMSeverity := processSeverity
			if severityRank(memSeverity) > severityRank(topRAMSeverity) {
				topRAMSeverity = memSeverity
			}
			renderProcesses(w, width, sectionLabel("Top RAM", topRAMSeverity, o.Color), withoutPIDs(p.TopRSS, p.TopCPU), separator, p.CPUSampled)
		}
	}
	renderIntegrations(w, width, r, separator, o.Color, o.Verbose, o.Quiet)
	if o.Events || o.EventsAll || r.Score.Status == model.SeverityCritical {
		renderTimeline(w, width, r, o.Color, o.EventsAll)
	}
	findings := actionableFindings(r.Findings)
	if o.Verbose {
		findings = r.Findings
	}
	if len(findings) > 0 {
		fmt.Fprintln(w)
		writeWrapped(w, width, "", detailsHeader(o.Color))
		for _, f := range findings {
			writeWrapped(w, width, "", fmt.Sprintf("%s  %s", badge(f.Severity, o.Color), sectionLabel(cleanText(f.Title), f.Severity, o.Color)))
			if cleanText(f.Summary) != "" {
				writeWrapped(w, width, "    ", cleanText(f.Summary))
			}
			if len(f.Evidence) > 0 {
				limit := len(f.Evidence)
				if limit > 3 {
					limit = 3
				}
				for _, evidence := range f.Evidence[:limit] {
					line := cleanText(evidence.Value)
					if cleanText(evidence.Label) != "" {
						line = cleanText(evidence.Label) + ": " + line
					}
					writeWrapped(w, width, "    ", line)
				}
				if len(f.Evidence) > limit {
					writeWrapped(w, width, "    ", fmt.Sprintf("(%d more evidence items)", len(f.Evidence)-limit))
				}
			}
			if f.Suggestion != "" {
				writeWrapped(w, width, "    ", formatSuggestion(f.Suggestion, o.Color))
			}
		}
	} else if len(compactInformationalFindings(r.Findings)) == 0 {
		fmt.Fprintln(w)
		writeWrapped(w, width, "", "No actionable findings from the collected signals.")
	}
	if !o.Verbose {
		for _, finding := range compactInformationalFindings(r.Findings) {
			writeWrapped(w, width, "", fmt.Sprintf("%s  %s", badge(model.SeverityInfo, o.Color), highlightContainerName(cleanText(finding.Title), o.Color)))
		}
	}
}

// collectionSeverity maps a collector's raw status string to a display
// severity so collection notes use the same badge vocabulary as findings.
func collectionSeverity(status string) model.Severity {
	switch status {
	case "ok":
		return model.SeverityOK
	case "error":
		return model.SeverityWarning
	default:
		return model.SeverityInfo
	}
}

// collectionStatusFor looks up the collection status for a named collector.
func collectionStatusFor(r model.Report, collector string) (model.CollectionStatus, bool) {
	for _, status := range r.Collection {
		if status.Collector == collector {
			return status, true
		}
	}
	return model.CollectionStatus{}, false
}

// writeCollectionNote attaches a collector's diagnostic detail under the
// report row it belongs to, in verbose mode, instead of dumping every
// collector's status in a separate block disconnected from its metric.
// Successful checks with nothing to say produce no note.
func writeCollectionNote(w io.Writer, width int, r model.Report, collector string, color bool) {
	status, ok := collectionStatusFor(r, collector)
	if !ok || cleanText(status.Detail) == "" {
		return
	}
	severity := collectionSeverity(status.Status)
	writeWrapped(w, width, "    ", fmt.Sprintf("%s  %s", badge(severity, color), cleanText(status.Detail)))
}

// highlightContainerName colors the container name inside a "Container
// <name> logged ..." title so a run of otherwise-identical lines is easy to
// tell apart at a glance.
func highlightContainerName(title string, color bool) string {
	const prefix = "Container "
	if !color || !strings.HasPrefix(title, prefix) {
		return title
	}
	rest := strings.TrimPrefix(title, prefix)
	idx := strings.Index(rest, " logged ")
	if idx < 0 {
		return title
	}
	name, tail := rest[:idx], rest[idx:]
	return prefix + metadata(name, color) + tail
}

func detailsHeader(color bool) string {
	return sectionHeader("Details", color)
}

func sectionHeader(text string, color bool) string {
	if !color {
		return text
	}
	return "\x1b[35m" + text + "\x1b[0m"
}

// checkLine prints one atomic check as its own badged line: a label, its own
// OK/WARN/CRIT/INFO status, and the fact behind that status. Grouping several
// unrelated checks into one comma-separated line hides which one actually
// carries the badge; this keeps each check individually identifiable.
func checkLine(w io.Writer, width int, indent, label string, severity model.Severity, color bool, detail string) {
	line := fmt.Sprintf("%s %s", sectionLabel(label, severity, color), badge(severity, color))
	if detail != "" {
		line += "  " + detail
	}
	writeWrapped(w, width, indent, line)
}

func formatSuggestion(s string, color bool) string {
	s = cleanText(s)
	const prefix = "Review with "
	if !strings.HasPrefix(s, prefix) || !color {
		return s
	}
	return "\x1b[37m" + prefix + "\x1b[0m" + "\x1b[34m" + strings.TrimPrefix(s, prefix) + "\x1b[0m"
}

func sectionLabel(text string, severity model.Severity, color bool) string {
	if !color {
		return text
	}
	code := severityColorCode(severity)
	return "\x1b[1;" + code + "m" + text + "\x1b[0m"
}

func metadata(text string, color bool) string {
	if !color {
		return text
	}
	return "\x1b[34m" + text + "\x1b[0m"
}

func severityColorCode(severity model.Severity) string {
	code := "35"
	switch severity {
	case model.SeverityOK:
		code = "32"
	case model.SeverityInfo:
		code = "36"
	case model.SeverityWarning:
		code = "33"
	case model.SeverityCritical:
		code = "31"
	}
	return code
}

func badge(severity model.Severity, color bool) string {
	text := strings.ToUpper(string(severity))
	switch severity {
	case model.SeverityOK:
		text = "OK"
	case model.SeverityWarning:
		text = "WARN"
	case model.SeverityCritical:
		text = "CRIT"
	case model.SeverityUnknown, "":
		text = "UNKNOWN"
	}
	if !color {
		return text
	}
	return "\x1b[" + severityColorCode(severity) + "m" + text + "\x1b[0m"
}

func actionableFindings(findings []model.Finding) []model.Finding {
	result := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Severity == model.SeverityWarning || finding.Severity == model.SeverityCritical || finding.Severity == model.SeverityUnknown {
			result = append(result, finding)
		}
	}
	return result
}

func informationalFindings(findings []model.Finding) []model.Finding {
	result := make([]model.Finding, 0)
	for _, finding := range findings {
		if finding.Severity == model.SeverityInfo {
			result = append(result, finding)
		}
	}
	return result
}

// quietInfoFindingIDs holds informational finding IDs whose own check
// already states the same fact in its compact summary row (for example,
// Path MTU's row already says "reduced but working normally"). Repeating
// them as a generic one-line fact in the non-verbose report is redundant,
// and for a host with an intentional, permanent reduced MTU it never goes
// away -- so these stay out of the compact report and remain fully visible
// in --verbose and in JSON.
var quietInfoFindingIDs = map[string]bool{
	"path-mtu-reduced": true,
}

// compactInformationalFindings is informationalFindings filtered for the
// non-verbose report: it excludes findings already fully explained by their
// own row (see quietInfoFindingIDs).
func compactInformationalFindings(findings []model.Finding) []model.Finding {
	result := make([]model.Finding, 0)
	for _, finding := range informationalFindings(findings) {
		if quietInfoFindingIDs[finding.ID] {
			continue
		}
		result = append(result, finding)
	}
	return result
}

// findingSeverity returns the highest severity among findings whose ID
// exactly matches one of the given ids, or OK if none matched. Per-item
// verbose lines use this so their badge stays consistent with whatever the
// analyzer already decided, instead of re-deriving thresholds in the
// renderer.
func findingSeverity(findings []model.Finding, ids ...string) model.Severity {
	severity := model.SeverityOK
	for _, f := range findings {
		for _, id := range ids {
			if f.ID == id && severityRank(f.Severity) > severityRank(severity) {
				severity = f.Severity
			}
		}
	}
	return severity
}

// findingSeverityByPrefix is findingSeverity for IDs that embed a variable
// suffix (e.g. a network interface name) the caller cannot fully predict.
func findingSeverityByPrefix(findings []model.Finding, category, prefix string) model.Severity {
	severity := model.SeverityOK
	for _, f := range findings {
		if f.Category == category && strings.HasPrefix(f.ID, prefix) && severityRank(f.Severity) > severityRank(severity) {
			severity = f.Severity
		}
	}
	return severity
}

func maxSeverity(a, b model.Severity) model.Severity {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

func sectionSeverity(findings []model.Finding, category string) model.Severity {
	severity := model.SeverityOK
	for _, finding := range findings {
		if finding.Category != category || severityRank(finding.Severity) <= severityRank(severity) {
			continue
		}
		severity = finding.Severity
	}
	return severity
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 4
	case model.SeverityWarning:
		return 3
	case model.SeverityInfo:
		return 2
	case model.SeverityOK:
		return 1
	default:
		return 0
	}
}

func withoutPIDs(processes, alreadyShown []model.Process) []model.Process {
	seen := make(map[int]struct{}, len(alreadyShown))
	for _, process := range alreadyShown {
		seen[process.PID] = struct{}{}
	}
	result := make([]model.Process, 0, len(processes))
	for _, process := range processes {
		if _, exists := seen[process.PID]; !exists {
			result = append(result, process)
		}
	}
	return result
}

// size scales to the largest unit that keeps the number readable. Rendering
// every value in MiB is fine for a process's resident set but produces
// "23068672.0 MiB" for a filesystem, which no operator can read at a glance.
// fullestWritable returns the filesystem closest to full among those that can
// still be written to, falling back to the fullest overall when every mount is
// read-only.
func fullestWritable(filesystems []model.Filesystem) model.Filesystem {
	fullest := filesystems[0]
	found := false
	for _, fs := range filesystems {
		if fs.ReadOnly {
			continue
		}
		if !found || fs.UsedFraction > fullest.UsedFraction {
			fullest, found = fs, true
		}
	}
	if found {
		return fullest
	}
	for _, fs := range filesystems[1:] {
		if fs.UsedFraction > fullest.UsedFraction {
			fullest = fs
		}
	}
	return fullest
}

func size(v uint64) string {
	const unit = 1024.0
	value := float64(v)
	for _, suffix := range []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"} {
		if value < unit || suffix == "PiB" {
			if suffix == "B" {
				return fmt.Sprintf("%d B", v)
			}
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
		value /= unit
	}
	return fmt.Sprintf("%.1f PiB", value)
}

// sizeMiB keeps the fixed MiB unit for process resident memory, where a single
// unit makes entries directly comparable down a column.
func sizeMiB(v uint64) string { return fmt.Sprintf("%.1f MiB", float64(v)/(1024*1024)) }

func sizePerSecond(v uint64, seconds float64) string {
	if seconds <= 0 {
		return "0 B"
	}
	return size(uint64(float64(v) / seconds))
}
func hottestSensor(s []model.Thermal) model.Thermal {
	h := s[0]
	for _, v := range s[1:] {
		if v.TemperatureC > h.TemperatureC {
			h = v
		}
	}
	return h
}

func thermalLabel(name string) string {
	value := strings.ToLower(name)
	switch {
	case strings.Contains(value, "k10temp"), strings.Contains(value, "coretemp"), strings.Contains(value, "zenpower"), strings.Contains(value, "cpu"):
		return "CPU sensor"
	case strings.Contains(value, "nvme"):
		return "NVMe sensor"
	case strings.Contains(value, "drivetemp"):
		return "drive sensor"
	default:
		return "hardware sensor"
	}
}

func busiestDisk(disks []model.Disk) model.Disk {
	busiest := disks[0]
	for _, disk := range disks[1:] {
		if disk.Utilization > busiest.Utilization || (disk.Utilization == busiest.Utilization && disk.Name < busiest.Name) {
			busiest = disk
		}
	}
	return busiest
}

func diskKind(disks []model.Disk) string {
	virtual := 0
	for _, disk := range disks {
		name := strings.ToLower(disk.Name)
		if strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "xvd") {
			virtual++
		}
	}
	if virtual == len(disks) {
		if len(disks) == 1 {
			return "virtual disk"
		}
		return "virtual disks"
	}
	if len(disks) == 1 {
		return "physical disk"
	}
	return "physical disks"
}

// linkSummary describes the negotiated link when sysfs reported a speed. A
// virtual interface and a down port both report none, so the detail is omitted
// rather than shown as zero. Half duplex is named because it is nearly always
// accidental on current hardware; full duplex is the unremarkable default.
func linkSummary(iface model.Network) string {
	if iface.SpeedMbps == nil || *iface.SpeedMbps == 0 {
		return ""
	}
	speed := fmt.Sprintf("%d Mb/s", *iface.SpeedMbps)
	if *iface.SpeedMbps >= 1000 && *iface.SpeedMbps%1000 == 0 {
		speed = fmt.Sprintf("%d Gb/s", *iface.SpeedMbps/1000)
	}
	if strings.EqualFold(strings.TrimSpace(iface.Duplex), "half") {
		return " (" + speed + " half duplex)"
	}
	return " (" + speed + ")"
}

func busiestNetwork(interfaces []model.Network) model.Network {
	busiest := interfaces[0]
	for _, iface := range interfaces[1:] {
		if iface.RXBytes+iface.TXBytes > busiest.RXBytes+busiest.TXBytes || (iface.RXBytes+iface.TXBytes == busiest.RXBytes+busiest.TXBytes && iface.Name < busiest.Name) {
			busiest = iface
		}
	}
	return busiest
}

func timeSyncStatus(sync *model.TimeSync) string {
	if sync.Synchronized == nil {
		return cleanText(sync.Service) + " status unavailable"
	}
	if *sync.Synchronized {
		return cleanText(sync.Service) + " synchronized"
	}
	return cleanText(sync.Service) + " NOT synchronized"
}

func resourceSummary(resources *model.Resources) string {
	var parts []string
	for _, limit := range []struct {
		name string
		used uint64
		max  uint64
	}{
		{"FDs", resources.OpenFiles, resources.OpenFilesMaximum},
		// Tasks are measured against the ceiling they actually reach, matching
		// the rule analysis applies rather than pid_max on its own.
		{"tasks", resources.Processes, taskCeiling(resources)},
		{"conntrack", resources.Conntrack, resources.ConntrackMaximum},
	} {
		if limit.max > 0 {
			parts = append(parts, fmt.Sprintf("%s %d/%d (%.0f%%)", limit.name, limit.used, limit.max, float64(limit.used)*100/float64(limit.max)))
		}
	}
	return strings.Join(parts, "; ")
}

// taskCeiling mirrors the analyzer: whichever of threads-max and pid_max is
// reached first is the limit a task count approaches.
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

func writeWrapped(w io.Writer, width int, indent, text string) {
	available := width - displayWidth(indent)
	if available < 1 {
		available = 1
	}
	if displayWidth(text) <= available {
		fmt.Fprintln(w, indent+text)
		return
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		fmt.Fprintln(w, indent)
		return
	}
	line := indent
	used := 0
	for _, word := range words {
		wordWidth := displayWidth(word)
		additional := wordWidth
		if used > 0 {
			additional++
		}
		if used > 0 && used+additional > available {
			fmt.Fprintln(w, line)
			if additional > available {
				chunks := splitDisplay(word, available)
				for _, chunk := range chunks[:len(chunks)-1] {
					fmt.Fprintln(w, indent+chunk)
				}
				line, used = indent+chunks[len(chunks)-1], displayWidth(chunks[len(chunks)-1])
			} else {
				line, used = indent+word, wordWidth
			}
			continue
		}
		if used == 0 && additional > available {
			chunks := splitDisplay(word, available)
			for _, chunk := range chunks[:len(chunks)-1] {
				fmt.Fprintln(w, indent+chunk)
			}
			line, used = indent+chunks[len(chunks)-1], displayWidth(chunks[len(chunks)-1])
			continue
		}
		if used > 0 {
			line += " "
		}
		line += word
		used += additional
	}
	fmt.Fprintln(w, line)
}

func renderProcesses(w io.Writer, width int, label string, processes []model.Process, separator string, sampled *bool) {
	if len(processes) == 0 {
		return
	}
	limit := len(processes)
	if limit > 3 {
		limit = 3
	}
	writeWrapped(w, width, "", label+separator+"processes (CPU: % of one core; RAM: resident/RSS)")
	for _, p := range processes[:limit] {
		cpu := fmt.Sprintf("%.1f%%", p.CPUFraction*100)
		if (sampled != nil && !*sampled) || (p.CPUSampled != nil && !*p.CPUSampled) {
			cpu = "unavailable"
		}
		writeWrapped(w, width, "    ", fmt.Sprintf("%s (pid %d)%sCPU %s%sRAM %s", cleanText(p.Command), p.PID, separator, cpu, separator, sizeMiB(p.RSSBytes)))
	}
	if len(processes) > limit {
		writeWrapped(w, width, "    ", fmt.Sprintf("(%d more processes)", len(processes)-limit))
	}
}

// SafeText removes terminal control characters from externally sourced text.
// Newlines and tabs become spaces so a value cannot forge report lines.
func SafeText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			b.WriteByte(' ')
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			b.WriteRune('�')
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func cleanText(s string) string { return SafeText(s) }

func displayWidth(s string) int {
	w := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
				i++
			}
			if i < len(s) {
				i++
			}
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		if n == 0 {
			break
		}
		i += n
		if r == '\n' || r == '\r' {
			continue
		}
		if unicode.Is(unicode.Mn, r) {
			continue
		}
		if r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a || (r >= 0x2e80 && r <= 0xa4cf) || (r >= 0xac00 && r <= 0xd7a3) || (r >= 0xf900 && r <= 0xfaff) || r >= 0xff01) {
			w += 2
		} else {
			w++
		}
	}
	return w
}

func splitDisplay(s string, width int) []string {
	if width < 1 {
		width = 1
	}
	var out []string
	start, used := 0, 0
	last := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
				i++
			}
			if i < len(s) {
				i++
			}
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		if n == 0 {
			break
		}
		cw := displayWidth(string(r))
		if used+cw > width && i > start {
			out = append(out, s[start:last])
			start = last
			used = 0
		}
		i += n
		last = i
		used += cw
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

func nonEmpty(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = cleanText(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func cpuUtilization(c *model.CPU) string {
	if c.Sampled != nil && !*c.Sampled {
		return "utilization unavailable"
	}
	return fmt.Sprintf("%.0f%% avg", c.Utilization*100)
}

func swapUsed(m *model.Memory) uint64 {
	if m.SwapFreeBytes > m.SwapTotalBytes {
		return 0
	}
	return m.SwapTotalBytes - m.SwapFreeBytes
}
