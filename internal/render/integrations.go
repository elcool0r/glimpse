package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/elcool0r/glimpse/internal/model"
)

// renderIntegrations renders one row per optional check, each followed
// immediately (in verbose mode) by that same check's own detail lines and
// any collection diagnostic for it. Detail always sits directly under the
// row it belongs to; nothing is appended in a separate pass at the end.
func renderIntegrations(w io.Writer, width int, r model.Report, separator string, color, verbose, quiet bool) {
	m := r.Metrics
	note := func(collector string) {
		if verbose {
			writeCollectionNote(w, width, r, collector, color)
		}
	}
	skip := func(severity model.Severity) bool {
		return quiet && severity == model.SeverityOK
	}
	for _, runtime := range m.Containers {
		running, unhealthy, restarting, logIssues, oomKilled, exited := 0, 0, 0, 0, 0, 0
		restarts := 0
		for _, c := range runtime.Containers {
			if strings.EqualFold(c.State, "running") {
				running++
			}
			if strings.EqualFold(c.State, "restarting") {
				restarting++
			}
			if c.Healthy != nil && !*c.Healthy {
				unhealthy++
			}
			if len(c.LogEvents) > 0 {
				logIssues++
			}
			if c.OOMKilled {
				oomKilled++
			}
			if strings.EqualFold(c.State, "exited") {
				exited++
			}
			if c.RestartCount > 0 {
				restarts++
			}
		}
		// Findings own the health verdict. Counts remain useful context, but
		// must not turn intentional exited containers or generic log wording
		// into a warning independently of the analyzer.
		severity := model.SeverityOK
		for _, c := range runtime.Containers {
			name := c.Name
			if name == "" {
				name = c.ID
			}
			severity = maxSeverity(severity, findingSeverityByPrefix(r.Findings, "containers", "container-"+runtime.Runtime+"-"+name+"-"))
		}
		coverageLimited := runtime.ContainerInspectionLimited || runtime.ContainersInspected < runtime.ContainersDiscovered || runtime.LogCheckLimited || runtime.LogsChecked < runtime.LogCandidates
		if coverageLimited && severity == model.SeverityOK {
			severity = model.SeverityInfo
		}
		text := fmt.Sprintf("%s %s  %s%s%d running", sectionLabel("Containers", severity, color), badge(severity, color), cleanText(runtime.Runtime), separator, running)
		if runtime.ContainerInspectionLimited || runtime.ContainersInspected < runtime.ContainersDiscovered {
			text += fmt.Sprintf("%sinspect: %d/%d (inspection limit)", separator, runtime.ContainersInspected, runtime.ContainersDiscovered)
		}
		if runtime.LogCandidates > 0 {
			text += fmt.Sprintf("%slogs: %d/%d checked", separator, runtime.LogsChecked, runtime.LogCandidates)
			if runtime.LogCheckLimited || runtime.LogsChecked < runtime.LogCandidates {
				text += " (time limit)"
			}
		}
		if unhealthy > 0 {
			text += fmt.Sprintf("%s%d unhealthy", separator, unhealthy)
		}
		if restarting > 0 {
			text += fmt.Sprintf("%s%d restarting", separator, restarting)
		}
		if exited > 0 {
			text += fmt.Sprintf("%s%d exited", separator, exited)
		}
		if restarts > 0 {
			text += fmt.Sprintf("%s%d restarted", separator, restarts)
		}
		if logIssues > 0 {
			label := "log issues"
			if logIssues == 1 {
				label = "log issue"
			}
			text += fmt.Sprintf("%s%d %s", separator, logIssues, label)
		}
		if oomKilled > 0 {
			text += fmt.Sprintf("%s%d OOM-killed", separator, oomKilled)
		}
		if !skip(severity) {
			writeWrapped(w, width, "", text)
			if verbose {
				for _, c := range runtime.Containers {
					name := c.Name
					if name == "" {
						name = c.ID
					}
					prefix := "container-" + runtime.Runtime + "-" + name
					containerSeverity := findingSeverityByPrefix(r.Findings, "containers", prefix+"-")
					detail := cleanText(c.State)
					if c.Healthy != nil {
						if *c.Healthy {
							detail += separator + "healthy"
						} else {
							detail += separator + "unhealthy"
						}
					}
					if c.RestartCount > 0 {
						detail += fmt.Sprintf("%s%d restart(s)", separator, c.RestartCount)
					}
					if len(c.LogEvents) > 0 {
						detail += fmt.Sprintf("%s%d log event(s)", separator, len(c.LogEvents))
					}
					checkLine(w, width, "    ", cleanText(name), containerSeverity, color, detail)
				}
			}
		}
	}
	note("containers")

	for _, pool := range m.ZFSPools {
		health := cleanText(pool.Health)
		if health == "" {
			health = "UNKNOWN"
		}
		healthSeverity := model.SeverityOK
		if !strings.EqualFold(health, "ONLINE") {
			healthSeverity = model.SeverityCritical
		}
		errorsSeverity := model.SeverityOK
		if pool.PermanentErrors {
			errorsSeverity = model.SeverityCritical
		} else if zfsPoolHasErrors(pool) {
			errorsSeverity = model.SeverityWarning
		}
		severity := healthSeverity
		if severityRank(errorsSeverity) > severityRank(severity) {
			severity = errorsSeverity
		}
		if !skip(severity) {
			writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s", sectionLabel("ZFS", severity, color), badge(severity, color), cleanText(pool.Name)))
			if verbose {
				checkLine(w, width, "    ", "Pool health", healthSeverity, color, health)
				errorsDetail := fmt.Sprintf("root row read %d%swrite %d%schecksum %d", pool.ReadErrors, separator, pool.WriteErrors, separator, pool.ChecksumErrors)
				if pool.Approximate || zfsVdevApproximate(pool.VdevErrors) {
					errorsDetail += separator + "some counters approximate"
				}
				if pool.PermanentErrors {
					errorsDetail += separator + "permanent errors present"
				}
				checkLine(w, width, "    ", "Data integrity", errorsSeverity, color, errorsDetail)
				for _, vdev := range pool.VdevErrors {
					vdevDetail := fmt.Sprintf("%s: read %d%swrite %d%schecksum %d", cleanText(vdev.State), vdev.ReadErrors, separator, vdev.WriteErrors, separator, vdev.ChecksumErrors)
					if vdev.Approximate {
						vdevDetail += separator + "approximate counters"
					}
					checkLine(w, width, "    ", "Vdev "+cleanText(vdev.Name), model.SeverityWarning, color, vdevDetail)
				}
				scanSeverity := model.SeverityOK
				scanDetail := cleanText(pool.ScanState)
				if scanDetail == "" {
					scanDetail = "no scrub/resilver recorded"
				} else if strings.Contains(strings.ToLower(scanDetail), "in progress") {
					scanSeverity = model.SeverityInfo
				}
				checkLine(w, width, "    ", "Scrub/resilver", scanSeverity, color, scanDetail)
			} else if healthSeverity != model.SeverityOK || errorsSeverity != model.SeverityOK {
				detail := fmt.Sprintf("health %s%sroot row errors read %d/write %d/checksum %d", health, separator, pool.ReadErrors, pool.WriteErrors, pool.ChecksumErrors)
				if len(pool.VdevErrors) > 0 {
					names := make([]string, 0, len(pool.VdevErrors))
					for _, vdev := range pool.VdevErrors {
						names = append(names, cleanText(vdev.Name))
					}
					detail += separator + "vdevs " + strings.Join(names, ", ")
				}
				writeWrapped(w, width, "    ", detail)
			}
		}
	}
	note("zfs")
	if len(m.SoftwareRAID) > 0 || m.LVM != nil || len(m.MountChecks) > 0 {
		raidSeverity := findingSeverityByPrefix(r.Findings, "storage", "raid-")
		lvmSeverity := findingSeverityByPrefix(r.Findings, "storage", "lvm-")
		mountSeverity := findingSeverityByPrefix(r.Findings, "storage", "mount-missing-")
		storageStatus, storageLimited := collectionStatusFor(r, "storage")
		severity := maxSeverity(raidSeverity, maxSeverity(lvmSeverity, mountSeverity))
		if storageLimited && strings.Contains(storageStatus.Detail, "LVM metadata could not be read") {
			severity = maxSeverity(severity, collectionSeverity(storageStatus.Status))
		}
		raidCount := len(m.SoftwareRAID)
		parts := []string{}
		if raidCount > 0 {
			parts = append(parts, fmt.Sprintf("RAID %d checked", raidCount))
		}
		if m.LVM != nil {
			parts = append(parts, fmt.Sprintf("LVM %d PV/%d VG/%d LV", len(m.LVM.PhysicalVolumes), len(m.LVM.VolumeGroups), len(m.LVM.LogicalVolumes)))
		} else if storageLimited && strings.Contains(storageStatus.Detail, "LVM metadata could not be read") {
			parts = append(parts, "LVM coverage requires sudo")
		}
		if len(m.MountChecks) > 0 {
			active, known := 0, 0
			for _, mount := range m.MountChecks {
				if mount.ActiveKnown {
					known++
				}
				if mount.ActiveKnown && mount.Active {
					active++
				}
			}
			if known == 0 {
				parts = append(parts, fmt.Sprintf("mounts %d listed", len(m.MountChecks)))
			} else {
				parts = append(parts, fmt.Sprintf("mounts %d/%d active", active, len(m.MountChecks)))
			}
		}
		if !skip(severity) {
			writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s", sectionLabel("Storage layers", severity, color), badge(severity, color), strings.Join(parts, separator)))
			if verbose {
				for _, raid := range m.SoftwareRAID {
					itemSeverity := findingSeverity(r.Findings, "raid-"+raid.Device, "raid-resync-"+raid.Device)
					text := fmt.Sprintf("%s %s  %s%s%s%s%s", sectionLabel("RAID", itemSeverity, color), badge(itemSeverity, color), cleanText(raid.Device), separator, cleanText(raid.Level), separator, cleanText(raid.State))
					if raid.ResyncProgress != "" {
						text += separator + "rebuild/resync active"
					}
					writeWrapped(w, width, "    ", text)
				}
				if m.LVM != nil {
					writeWrapped(w, width, "    ", fmt.Sprintf("%s %s  %d PVs%s%d VGs%s%d LVs", sectionLabel("LVM", lvmSeverity, color), badge(lvmSeverity, color), len(m.LVM.PhysicalVolumes), separator, len(m.LVM.VolumeGroups), separator, len(m.LVM.LogicalVolumes)))
				}
				if len(m.MountChecks) > 0 {
					active := 0
					for _, mount := range m.MountChecks {
						if mount.Active {
							active++
						}
					}
					writeWrapped(w, width, "    ", fmt.Sprintf("%s %s  fstab mounts %d/%d active", sectionLabel("Mounts", mountSeverity, color), badge(mountSeverity, color), active, len(m.MountChecks)))
					for _, mount := range m.MountChecks {
						itemSeverity := findingSeverity(r.Findings, "mount-missing-"+mount.MountPoint)
						status := "active"
						if mount.ActiveKnown && !mount.Active {
							status = "not active"
						} else if !mount.ActiveKnown {
							status = "activity unknown"
						}
						detail := fmt.Sprintf("%s%s%s", cleanText(mount.FSType), separator, status)
						checkLine(w, width, "        ", cleanText(mount.MountPoint), itemSeverity, color, detail)
					}
				}
			} else if storageLimited && strings.Contains(storageStatus.Detail, "LVM metadata could not be read") {
				checkLine(w, width, "    ", "LVM metadata", collectionSeverity(storageStatus.Status), color, cleanText(storageStatus.Detail))
			}
		}
	}
	note("storage")

	if len(m.DeviceHealth) > 0 || m.DeviceHealthCoverage != nil && m.DeviceHealthCoverage.DevicesEligible > 0 {
		// Device health had no default-report row at all, so a scan that ran
		// out of time and skipped most disks looked identical to a clean sweep.
		severity := model.SeverityOK
		attention := 0
		for _, device := range m.DeviceHealth {
			if device.OverallPassed != nil && !*device.OverallPassed || device.CriticalWarning != 0 ||
				device.PendingSectors != 0 || device.Uncorrectable != 0 || device.MediaErrors != 0 {
				attention++
			}
			severity = maxSeverity(severity, findingSeverity(r.Findings, "device-health-"+device.Device, "device-wear-"+device.Device))
		}
		coverage := m.DeviceHealthCoverage
		coverageLimited := coverage != nil && (coverage.Limited || coverage.DevicesChecked < coverage.DevicesEligible)
		if coverageLimited && severity == model.SeverityOK {
			severity = model.SeverityInfo
		}
		text := fmt.Sprintf("%s %s  %d device(s) checked", sectionLabel("Devices", severity, color), badge(severity, color), len(m.DeviceHealth))
		if coverage != nil && coverage.DevicesEligible > 0 {
			text = fmt.Sprintf("%s %s  %d/%d device(s) checked", sectionLabel("Devices", severity, color), badge(severity, color), coverage.DevicesChecked, coverage.DevicesEligible)
			if coverageLimited && coverage.Reason != "" {
				text += fmt.Sprintf(" (%s)", cleanText(coverage.Reason))
			}
		}
		if attention > 0 {
			text += fmt.Sprintf("%s%d needing attention", separator, attention)
		}
		if !skip(severity) {
			writeWrapped(w, width, "", text)
			if verbose {
				for _, device := range m.DeviceHealth {
					deviceSeverity := findingSeverity(r.Findings, "device-health-"+device.Device, "device-wear-"+device.Device)
					var facts []string
					if device.OverallPassed != nil {
						if *device.OverallPassed {
							facts = append(facts, "SMART passed")
						} else {
							facts = append(facts, "SMART FAILED")
						}
					}
					if device.CriticalWarning != 0 {
						facts = append(facts, fmt.Sprintf("critical warning 0x%x", device.CriticalWarning))
					}
					if device.PendingSectors != 0 {
						facts = append(facts, fmt.Sprintf("pending sectors %d", device.PendingSectors))
					}
					if device.Uncorrectable != 0 {
						facts = append(facts, fmt.Sprintf("uncorrectable %d", device.Uncorrectable))
					}
					if device.MediaErrors != 0 {
						facts = append(facts, fmt.Sprintf("media errors %d", device.MediaErrors))
					}
					if device.ReallocatedSectors != 0 {
						facts = append(facts, fmt.Sprintf("reallocated %d", device.ReallocatedSectors))
					}
					if device.TemperatureC != 0 {
						facts = append(facts, fmt.Sprintf("%.0f°C", device.TemperatureC))
					}
					if len(facts) == 0 {
						facts = append(facts, "no issues reported")
					}
					checkLine(w, width, "    ", cleanText(device.Device), deviceSeverity, color, strings.Join(facts, separator))
				}
			}
		}
	}
	note("device-health")

	if state := m.NetworkState; state != nil && state.Available {
		routes := "routes unavailable"
		if state.RoutesAvailable {
			routes = fmt.Sprintf("%d routes", len(state.Routes))
		}
		dnsSeverity, dnsText := dnsStatus(state, m.Systemd)
		if !skip(dnsSeverity) {
			writeWrapped(w, width, "", fmt.Sprintf("%s %s  %d listening sockets%s%s%s%d connection states%sDNS: %s", sectionLabel("Network state", dnsSeverity, color), badge(dnsSeverity, color), len(state.ListeningSockets), separator, routes, separator, len(state.ConnectionStates), separator, dnsText))
			if verbose {
				dnsDetail := dnsText
				if dnsSeverity == model.SeverityOK && state.DNS != nil && len(state.DNS.Nameservers) > 0 {
					dnsDetail = "Nameservers: " + strings.Join(cleanTexts(state.DNS.Nameservers), separator)
				}
				checkLine(w, width, "    ", "DNS configured", dnsSeverity, color, dnsDetail)
				routesSeverity := model.SeverityInfo
				routesDetail := "unavailable"
				if state.RoutesAvailable {
					routesSeverity = model.SeverityOK
					routesDetail = fmt.Sprintf("%d route(s)", len(state.Routes))
				}
				checkLine(w, width, "    ", "Routes", routesSeverity, color, routesDetail)
				socketsDetail := fmt.Sprintf("%d socket(s)", len(state.ListeningSockets))
				if len(state.ListeningSockets) > 0 {
					ports := make([]string, 0, len(state.ListeningSockets))
					for i, socket := range state.ListeningSockets {
						if i >= 8 {
							break
						}
						ports = append(ports, fmt.Sprintf("%s/%d", cleanText(socket.Protocol), socket.Port))
					}
					socketsDetail += ": " + strings.Join(ports, separator)
				}
				checkLine(w, width, "    ", "Listening sockets", model.SeverityOK, color, socketsDetail)
				connectionsDetail := "none observed"
				if len(state.ConnectionStates) > 0 {
					states := make([]string, 0, len(state.ConnectionStates))
					for _, connection := range state.ConnectionStates {
						states = append(states, fmt.Sprintf("%s %d", cleanText(connection.State), connection.Count))
					}
					connectionsDetail = strings.Join(states, separator)
				}
				checkLine(w, width, "    ", "Connection states", model.SeverityOK, color, connectionsDetail)
			}
		}
	}
	note("network-state")

	if resolution := m.DNSResolution; resolution != nil && resolution.Available {
		localSeverity := model.SeverityOK
		if resolution.Local != nil {
			localSeverity = findingSeverity(r.Findings, "dns-resolution-failed", "dns-resolution-local-failed", "dns-resolution-local-slow")
		}
		externalSeverity := findingSeverity(r.Findings, "dns-resolution-failed", "dns-resolution-external-failed", "dns-resolution-external-slow")
		severity := localSeverity
		if severityRank(externalSeverity) > severityRank(severity) {
			severity = externalSeverity
		}
		summary := func(result *model.DNSResolutionResult) string {
			if result == nil {
				return "not attempted"
			}
			if result.Resolved {
				return "ok"
			}
			return "failed"
		}
		if !skip(severity) {
			writeWrapped(w, width, "", fmt.Sprintf("%s %s  local: %s%sexternal: %s", sectionLabel("DNS resolution", severity, color), badge(severity, color), summary(resolution.Local), separator, summary(resolution.External)))
			if verbose {
				detail := func(result *model.DNSResolutionResult) string {
					if result == nil {
						return "no local nameserver configured"
					}
					if result.Resolved {
						return fmt.Sprintf("resolved %s via %s in %.0fms", cleanText(result.Domain), cleanText(result.Server), result.LatencyMillis)
					}
					return fmt.Sprintf("failed to resolve %s via %s: %s", cleanText(result.Domain), cleanText(result.Server), cleanText(result.Error))
				}
				checkLine(w, width, "    ", "Local resolution", localSeverity, color, detail(resolution.Local))
				checkLine(w, width, "    ", "External resolution", externalSeverity, color, detail(resolution.External))
			}
		}
	}
	note("dns-resolution")

	if check := m.GatewayCheck; check != nil && check.Available {
		severity := findingSeverity(r.Findings, "gateway-unreachable", "gateway-packet-loss", "gateway-high-latency")
		if !skip(severity) {
			writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s%s%d/%d replies%s%.0f%% loss", sectionLabel("Gateway", severity, color), badge(severity, color), cleanText(check.Gateway), separator, check.Received, check.Sent, separator, check.PacketLossPct))
			if verbose && check.Received > 0 {
				checkLine(w, width, "    ", "Latency", severity, color, fmt.Sprintf("%.1fms average", check.AvgLatencyMillis))
			}
		}
	}
	note("gateway-ping")

	if check := m.PathMTUCheck; check != nil && check.Available {
		severity := findingSeverity(r.Findings, "path-mtu-blackhole", "path-mtu-reduced")
		result := fmt.Sprintf("%d-byte IPv4 DF probe replied", check.CeilingMTU)
		switch {
		case check.DiscoveredMTU == 0:
			result = fmt.Sprintf("no IPv4 DF echo replies from %d down to %d bytes", check.CeilingMTU, check.FloorMTU)
		case check.DiscoveredMTU < check.CeilingMTU:
			result = fmt.Sprintf("largest tested IPv4 DF echo reply: %d/%d bytes", check.DiscoveredMTU, check.CeilingMTU)
			if check.PacketTooBigFeedback {
				result += separator + "packet-too-big feedback received"
			}
		}
		if check.DiscoveredMTU == 0 {
			if check.PacketTooBigFeedback {
				result += separator + "packet-too-big feedback observed"
			} else {
				result += separator + "no packet-too-big feedback observed"
			}
		}
		// The reduced-size INFO observation is quiet by default and remains
		// available under --verbose. OK and WARN/CRIT rows always show.
		if !skip(severity) {
			if verbose || severity != model.SeverityInfo {
				writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s%s%s", sectionLabel("Path MTU", severity, color), badge(severity, color), cleanText(check.Target), separator, result))
			}
			if verbose {
				checkLine(w, width, "    ", "Baseline (small packet)", model.SeverityOK, color, "echo reply received")
				mtuSeverity := model.SeverityOK
				mtuDetail := fmt.Sprintf("%d bytes; largest tested IPv4 DF packet replied", check.DiscoveredMTU)
				switch {
				case check.DiscoveredMTU == 0:
					mtuSeverity = severity
					mtuDetail = fmt.Sprintf("no echo replies from tested sizes %d down to %d bytes", check.CeilingMTU, check.FloorMTU)
				case check.DiscoveredMTU < check.CeilingMTU:
					if check.PacketTooBigFeedback {
						mtuDetail = fmt.Sprintf("%d bytes; packet-too-big feedback received for larger tested sizes up to %d bytes", check.DiscoveredMTU, check.CeilingMTU)
					} else {
						mtuSeverity = severity
						mtuDetail = fmt.Sprintf("%d bytes; larger tested sizes up to %d bytes did not reply", check.DiscoveredMTU, check.CeilingMTU)
					}
				}
				checkLine(w, width, "    ", "Largest tested IPv4 DF reply", mtuSeverity, color, mtuDetail)
				feedback := "not observed in probe output"
				if check.PacketTooBigFeedback {
					feedback = "observed in probe output"
				}
				feedbackSeverity := model.SeverityInfo
				if check.PacketTooBigFeedback {
					feedbackSeverity = model.SeverityOK
				}
				checkLine(w, width, "    ", "Packet-too-big feedback", feedbackSeverity, color, feedback)
			}
		}
	}
	note("path-mtu")

	if check := m.HTTPCheck; check != nil && check.Available {
		httpSeverity := findingSeverity(r.Findings, "http-check-failed", "http-check-http-failed", "http-check-proxy-used")
		httpsSeverity := findingSeverity(r.Findings, "http-check-failed", "https-check-failed", "http-check-proxy-used")
		severity := httpSeverity
		if severityRank(httpsSeverity) > severityRank(severity) {
			severity = httpsSeverity
		}
		summary := func(result *model.HTTPCheckResult) string {
			if result == nil {
				return "not attempted"
			}
			if result.Succeeded {
				return fmt.Sprintf("ok (%d)", result.StatusCode)
			}
			return "failed"
		}
		if !skip(severity) {
			proxyText := ""
			if check.HTTP != nil && check.HTTP.ProxyUsed || check.HTTPS != nil && check.HTTPS.ProxyUsed {
				proxyText = separator + "proxy used"
			}
			writeWrapped(w, width, "", fmt.Sprintf("%s %s  http: %s%shttps: %s%s", sectionLabel("HTTP checks", severity, color), badge(severity, color), summary(check.HTTP), separator, summary(check.HTTPS), proxyText))
			if verbose {
				detail := func(result *model.HTTPCheckResult) string {
					if result == nil {
						return "not attempted"
					}
					if result.Succeeded {
						detail := fmt.Sprintf("%s -> %d in %.0fms", cleanText(result.URL), result.StatusCode, result.LatencyMillis)
						if result.ProxyUsed {
							detail += separator + "proxy used"
						}
						return detail
					}
					return fmt.Sprintf("%s failed: %s", cleanText(result.URL), cleanText(result.Error))
				}
				checkLine(w, width, "    ", "HTTP", httpSeverity, color, detail(check.HTTP))
				checkLine(w, width, "    ", "HTTPS", httpsSeverity, color, detail(check.HTTPS))
			}
		}
	}
	note("http-check")

	if check := m.ICMPCheck; check != nil && check.Available {
		severity := findingSeverity(r.Findings, "icmp-external-unreachable", "icmp-external-packet-loss", "icmp-external-high-latency")
		if !skip(severity) {
			writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s%s%d/%d replies%s%.0f%% loss", sectionLabel("External ICMP", severity, color), badge(severity, color), cleanText(check.Target), separator, check.Received, check.Sent, separator, check.PacketLossPct))
			if verbose && check.Received > 0 {
				checkLine(w, width, "    ", "Latency", model.SeverityOK, color, fmt.Sprintf("%.1fms average", check.AvgLatencyMillis))
			}
		}
	}
	note("icmp-check")

	if check := m.IPv6Check; check != nil && check.Available {
		severity := findingSeverity(r.Findings, "ipv6-unreachable", "ipv6-packet-loss")
		if !skip(severity) {
			writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s%s%d/%d replies%s%.0f%% loss", sectionLabel("IPv6", severity, color), badge(severity, color), cleanText(check.Target), separator, check.Received, check.Sent, separator, check.PacketLossPct))
			if verbose && check.Received > 0 {
				checkLine(w, width, "    ", "Latency", model.SeverityOK, color, fmt.Sprintf("%.1fms average", check.AvgLatencyMillis))
			}
		}
	}
	note("ipv6-check")

	if df := m.DeletedFiles; df != nil && df.Available {
		severity := findingSeverity(r.Findings, "deleted-files-open")
		eligible := df.ProcessesEligible
		if eligible == 0 {
			eligible = df.ProcessesScanned + df.ProcessesSkipped
		}
		coverageLimited := df.ProcessScanLimited || df.ProcessesSkipped > 0
		if coverageLimited && severity == model.SeverityOK {
			severity = model.SeverityInfo
		}
		if !skip(severity) {
			text := fmt.Sprintf("%s %s  %s across %d unique file(s)%s%d process(es) holding", sectionLabel("Deleted files", severity, color), badge(severity, color), size(df.TotalBytes), df.UniqueFiles, separator, df.ProcessesHolding)
			if coverageLimited {
				reasons := make([]string, 0, 2)
				if df.ProcessScanLimited {
					reasons = append(reasons, "process limit")
				}
				if df.ProcessesSkipped > 0 {
					reasons = append(reasons, "permission")
				}
				text += fmt.Sprintf("%scoverage %d/%d checked (%s)", separator, df.ProcessesScanned, eligible, strings.Join(reasons, ", "))
			}
			writeWrapped(w, width, "", text)
			if verbose {
				coverageSeverity := model.SeverityOK
				if coverageLimited {
					coverageSeverity = model.SeverityInfo
				}
				checkLine(w, width, "    ", "Coverage", coverageSeverity, color, fmt.Sprintf("%d/%d process(es) checked%s%d skipped (permission)%s%d total reference(s)", df.ProcessesScanned, eligible, separator, df.ProcessesSkipped, separator, df.TotalReferences))
				if df.LargestHolderBytes > 0 {
					label := df.LargestHolderCommand
					if label == "" {
						label = fmt.Sprintf("pid %d", df.LargestHolderPID)
					}
					checkLine(w, width, "    ", "Largest holder", severity, color, fmt.Sprintf("%s (pid %d) -- %s across %d unique file(s)", cleanText(label), df.LargestHolderPID, size(df.LargestHolderBytes), df.LargestHolderFileCount))
				}
				// Grouped by unique inode, not by fd: a file held open on three
				// descriptors by one process appears once here with all three
				// listed as one holder, so the duplication is visible without
				// being counted three times.
				for i, f := range df.Files {
					if i >= 5 {
						break
					}
					holders := make([]string, 0, len(f.Holders))
					for _, h := range f.Holders {
						name := h.Command
						if name == "" {
							name = fmt.Sprintf("pid %d", h.PID)
						}
						holders = append(holders, fmt.Sprintf("%s (pid %d, fd %s)", cleanText(name), h.PID, strings.Join(h.FDs, ",")))
					}
					detail := fmt.Sprintf("%s at %s -- held by %s", size(f.Bytes), cleanText(f.Path), strings.Join(holders, "; "))
					checkLine(w, width, "    ", fmt.Sprintf("dev %s inode %d", cleanText(f.Device), f.Inode), severity, color, detail)
				}
			}
		}
	}
	note("deleted-files")

	if hardware := m.Hardware; hardware != nil && hardware.Available {
		severity := model.SeverityOK
		correctable, uncorrectable := uint64(0), uint64(0)
		for _, controller := range hardware.Controllers {
			correctable += controller.CorrectableErrors
			uncorrectable += controller.UncorrectableErrors
		}
		text := fmt.Sprintf("EDAC checked (%d controller(s))", len(hardware.Controllers))
		if correctable > 0 || uncorrectable > 0 {
			severity = model.SeverityInfo
			text += fmt.Sprintf("%scorrectable %d%suncorrectable %d", separator, correctable, separator, uncorrectable)
		}
		if !skip(severity) {
			writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s", sectionLabel("Hardware", severity, color), badge(severity, color), text))
			if verbose {
				for _, controller := range hardware.Controllers {
					severity := model.SeverityOK
					if controller.CorrectableErrors > 0 || controller.UncorrectableErrors > 0 {
						severity = model.SeverityInfo
					}
					checkLine(w, width, "    ", cleanText(controller.Name), severity, color, fmt.Sprintf("correctable %d%suncorrectable %d", controller.CorrectableErrors, separator, controller.UncorrectableErrors))
				}
			}
		}
	}
	note("hardware-errors")

	if k := m.Kernel; k != nil && k.Available {
		severity := sectionSeverity(r.Findings, "kernel")
		if !skip(severity) {
			writeWrapped(w, width, "", fmt.Sprintf("%s %s  %d pattern match(es) in kernel log", sectionLabel("Kernel", severity, color), badge(severity, color), len(k.Events)))
			if verbose {
				counts := make(map[string]int, len(k.Events))
				for _, event := range k.Events {
					counts[event.Kind]++
				}
				for _, kind := range kernelPatternKinds {
					count := counts[kind]
					delete(counts, kind)
					lineSeverity := findingSeverity(r.Findings, "kernel-"+kind)
					detail := "no matches"
					if count > 0 {
						detail = fmt.Sprintf("%d match(es)", count)
					}
					checkLine(w, width, "    ", cleanText(strings.ReplaceAll(kind, "_", " ")), lineSeverity, color, detail)
				}
				// Any kind the collector reports that this renderer does not yet
				// know about still needs to be visible rather than silently dropped.
				unknown := make([]string, 0, len(counts))
				for kind := range counts {
					unknown = append(unknown, kind)
				}
				sort.Strings(unknown)
				for _, kind := range unknown {
					// The collector's kind vocabulary is fixed, but an unknown kind
					// reaching here means it came from somewhere this renderer does
					// not control, so it is treated as untrusted text.
					checkLine(w, width, "    ", cleanText(strings.ReplaceAll(kind, "_", " ")), findingSeverity(r.Findings, "kernel-"+kind), color, fmt.Sprintf("%d match(es)", counts[kind]))
				}
			}
		}
	}
	note("kernel")

	if security := m.Security; security != nil && security.Available {
		severity := securityCheckSeverity(r, security)
		selinuxSkipped, apparmorSkipped, macSkipped := macFrameworkStatus(security)
		if !skip(severity) || macSkipped {
			selinuxStatus, apparmorStatus := cleanText(security.SELinux), cleanText(security.AppArmor)
			if selinuxSkipped {
				selinuxStatus = "skipped"
			}
			if apparmorSkipped {
				apparmorStatus = "skipped"
			}
			if macSkipped && severity == model.SeverityOK {
				writeWrapped(w, width, "", fmt.Sprintf("%s %s  SELinux %s%sAppArmor %s%sno MAC enforcement framework detected", skippedLabel("Security", color), skippedBadge(color), selinuxStatus, separator, apparmorStatus, separator))
			} else {
				writeWrapped(w, width, "", fmt.Sprintf("%s %s  SELinux %s%sAppArmor %s%ssecurity sources checked", sectionLabel("Security", severity, color), badge(severity, color), selinuxStatus, separator, apparmorStatus, separator))
			}
			if verbose {
				selinuxSeverity := maxSeverity(findingSeverity(r.Findings, "security-selinux-denials"), findingSeverity(r.Findings, "security-selinux-permissive"))
				selinuxDetail := cleanText(security.SELinux)
				if security.SELinuxDenials != nil {
					selinuxDetail += fmt.Sprintf("%s%d denial(s)", separator, *security.SELinuxDenials)
				}
				if selinuxSkipped && selinuxSeverity == model.SeverityOK {
					detail := "not detected; AppArmor is enabled"
					if macSkipped {
						detail = "not detected; no alternate MAC framework detected"
					}
					skippedCheckLine(w, width, "    ", "SELinux", color, detail)
				} else {
					checkLine(w, width, "    ", "SELinux", selinuxSeverity, color, selinuxDetail)
				}

				apparmorSeverity := findingSeverity(r.Findings, "security-apparmor-denials")
				apparmorDetail := cleanText(security.AppArmor)
				if security.AppArmorDenials != nil {
					apparmorDetail += fmt.Sprintf("%s%d denial(s)", separator, *security.AppArmorDenials)
				}
				if apparmorSkipped && apparmorSeverity == model.SeverityOK {
					detail := "not detected; SELinux is enforcing"
					if macSkipped {
						detail = "not detected; no alternate MAC framework detected"
					}
					skippedCheckLine(w, width, "    ", "AppArmor", color, detail)
				} else {
					checkLine(w, width, "    ", "AppArmor", apparmorSeverity, color, apparmorDetail)
				}

				if security.ActiveSessions != nil {
					checkLine(w, width, "    ", "Active sessions", model.SeverityOK, color, fmt.Sprintf("%d", *security.ActiveSessions))
				}
				if security.RebootRequired != nil && *security.RebootRequired {
					checkLine(w, width, "    ", "Reboot required", model.SeverityInfo, color, "pending package or kernel update")
				}
				if security.FailedAuthAttempts != nil && *security.FailedAuthAttempts > 0 {
					failedAuthSeverity := findingSeverity(r.Findings, "security-failed-auth")
					checkLine(w, width, "    ", "Failed authentication", failedAuthSeverity, color, fmt.Sprintf("%d event(s) in %s", *security.FailedAuthAttempts, cleanText(security.JournalWindow)))
				}
				if security.CoreDumps != nil && *security.CoreDumps > 0 {
					checkLine(w, width, "    ", "Core dumps", findingSeverity(r.Findings, "security-core-dumps"), color, fmt.Sprintf("%d recent dump(s)", *security.CoreDumps))
				}
				if len(security.CrashArtifacts) > 0 {
					checkLine(w, width, "    ", "Crash artifacts", model.SeverityInfo, color, fmt.Sprintf("%d artifact(s) present", len(security.CrashArtifacts)))
				}
				vulnerabilitySeverity := findingSeverityByPrefix(r.Findings, "security", "security-vulnerability-")
				if vulnerabilitySeverity != model.SeverityOK {
					checkLine(w, width, "    ", "Kernel vulnerabilities", vulnerabilitySeverity, color, "one or more statuses require review")
				}
				taintSeverity := model.SeverityOK
				taintDetail := "clean"
				if security.KernelTaintMask != 0 {
					taintSeverity = model.SeverityInfo
					taintDetail = fmt.Sprintf("mask %d", security.KernelTaintMask)
					if len(security.KernelTaintModules) > 0 {
						taintDetail += " (modules " + cleanText(strings.Join(security.KernelTaintModules, ",")) + ")"
					}
				}
				checkLine(w, width, "    ", "Kernel taint", taintSeverity, color, taintDetail)
			} else if security.KernelTaintMask != 0 {
				taintDetail := fmt.Sprintf("mask %d", security.KernelTaintMask)
				if len(security.KernelTaintModules) > 0 {
					taintDetail += " (modules " + cleanText(strings.Join(security.KernelTaintModules, ",")) + ")"
				}
				checkLine(w, width, "    ", "Kernel taint", model.SeverityInfo, color, taintDetail)
			}
		}
	}
	note("security")

	if cgroup := m.CgroupV2; cgroup != nil && cgroup.Available {
		severity := sectionSeverity(r.Findings, "cgroup")
		if skip(severity) {
			return
		}
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  containerized: %t", sectionLabel("Cgroup v2", severity, color), badge(severity, color), cgroup.Containerized))
		if verbose {
			checkLine(w, width, "    ", "Path", model.SeverityOK, color, cleanText(cgroup.Path))
			if !cgroupValid(cgroup.MemoryCurrentValid) {
				checkLine(w, width, "    ", "Memory current", model.SeverityUnknown, color, "unavailable")
			} else {
				checkLine(w, width, "    ", "Memory current", model.SeverityOK, color, fmt.Sprintf("%d bytes", cgroup.MemoryCurrentBytes))
			}
			if cgroup.MemoryMaxValid != nil && !*cgroup.MemoryMaxValid {
				checkLine(w, width, "    ", "Memory limit", model.SeverityUnknown, color, "unavailable")
			} else if cgroup.MemoryMaxBytes != nil && *cgroup.MemoryMaxBytes > 0 && cgroupValid(cgroup.MemoryCurrentValid) {
				fraction := float64(cgroup.MemoryCurrentBytes) * 100 / float64(*cgroup.MemoryMaxBytes)
				memSeverity := findingSeverity(r.Findings, "cgroup-memory-limit")
				checkLine(w, width, "    ", "Memory limit", memSeverity, color, fmt.Sprintf("%.0f%% used", fraction))
			} else if cgroup.MemoryMaxBytes != nil && *cgroup.MemoryMaxBytes > 0 {
				checkLine(w, width, "    ", "Memory limit", model.SeverityUnknown, color, fmt.Sprintf("%d bytes; usage unavailable", *cgroup.MemoryMaxBytes))
			} else if cgroup.MemoryMaxBytes != nil {
				checkLine(w, width, "    ", "Memory limit", model.SeverityOK, color, fmt.Sprintf("%d/%d bytes", cgroup.MemoryCurrentBytes, *cgroup.MemoryMaxBytes))
			} else {
				checkLine(w, width, "    ", "Memory limit", model.SeverityOK, color, "unlimited")
			}
			if !cgroupValid(cgroup.PIDsCurrentValid) {
				checkLine(w, width, "    ", "PIDs current", model.SeverityUnknown, color, "unavailable")
			} else {
				checkLine(w, width, "    ", "PIDs current", model.SeverityOK, color, fmt.Sprintf("%d", cgroup.PIDsCurrent))
			}
			if cgroup.PIDsMaxValid != nil && !*cgroup.PIDsMaxValid {
				checkLine(w, width, "    ", "PID limit", model.SeverityUnknown, color, "unavailable")
			} else if cgroup.PIDsMax != nil && *cgroup.PIDsMax > 0 && cgroupValid(cgroup.PIDsCurrentValid) {
				pidSeverity := findingSeverity(r.Findings, "cgroup-pids-limit")
				checkLine(w, width, "    ", "PID limit", pidSeverity, color, fmt.Sprintf("%d/%d", cgroup.PIDsCurrent, *cgroup.PIDsMax))
			} else if cgroup.PIDsMax != nil && *cgroup.PIDsMax > 0 {
				checkLine(w, width, "    ", "PID limit", model.SeverityUnknown, color, fmt.Sprintf("unavailable/%d", *cgroup.PIDsMax))
			} else if cgroup.PIDsMax != nil {
				checkLine(w, width, "    ", "PID limit", model.SeverityOK, color, fmt.Sprintf("%d/%d", cgroup.PIDsCurrent, *cgroup.PIDsMax))
			} else {
				checkLine(w, width, "    ", "PID limit", model.SeverityOK, color, "unlimited")
			}
			if cgroup.MemoryEventsSampled != nil && !*cgroup.MemoryEventsSampled {
				checkLine(w, width, "    ", "Memory events", model.SeverityUnknown, color, "sample unavailable")
			} else if cgroup.MemoryEventsSampled != nil {
				checkLine(w, width, "    ", "Memory events", model.SeverityOK, color, fmt.Sprintf("OOM %d, kills %d", cgroup.MemoryOOMDelta, cgroup.MemoryOOMKillDelta))
			}
			if cgroup.CPUStatSampled != nil && !*cgroup.CPUStatSampled {
				checkLine(w, width, "    ", "CPU statistics", model.SeverityUnknown, color, "sample unavailable")
			} else if cgroup.CPUStatSampled != nil {
				checkLine(w, width, "    ", "CPU statistics", model.SeverityOK, color, fmt.Sprintf("%.3fs used, %.3fs throttled", cgroup.CPUUsageSecondsDelta, cgroup.CPUThrottledSecondsDelta))
			}
		}
	}
	note("cgroup-v2")
}

// macFrameworkStatus identifies the common Linux configurations where one
// mandatory-access-control framework is intentionally absent because the
// other is active. It keeps that expected absence out of the health verdict.
func macFrameworkStatus(security *model.Security) (selinuxSkipped, apparmorSkipped, bothSkipped bool) {
	if security == nil {
		return false, false, false
	}
	selinux := strings.ToLower(strings.TrimSpace(security.SELinux))
	apparmor := strings.ToLower(strings.TrimSpace(security.AppArmor))
	selinuxUnknown := selinux == "" || selinux == "unknown"
	apparmorUnknown := apparmor == "" || apparmor == "unknown"
	if selinuxUnknown && apparmorUnknown {
		return true, true, true
	}
	return selinuxUnknown && apparmor == "enabled", apparmorUnknown && selinux == "enforcing", false
}

// securityCheckSeverity is intentionally limited to checks the security
// section renders. A section badge must always have corresponding visible
// evidence rather than inheriting an unrelated category-level INFO finding.
func securityCheckSeverity(r model.Report, security *model.Security) model.Severity {
	severity := maxSeverity(
		maxSeverity(
			findingSeverity(r.Findings, "security-selinux-denials", "security-selinux-permissive"),
			findingSeverity(r.Findings, "security-apparmor-denials"),
		),
		findingSeverity(r.Findings, "security-failed-auth", "security-core-dumps"),
	)
	severity = maxSeverity(severity, findingSeverityByPrefix(r.Findings, "security", "security-vulnerability-"))
	if security == nil {
		return severity
	}
	if security.KernelTaintMask != 0 || security.RebootRequired != nil && *security.RebootRequired || len(security.CrashArtifacts) > 0 {
		severity = maxSeverity(severity, model.SeverityInfo)
	}
	return severity
}

func cgroupValid(valid *bool) bool { return model.Measured(valid) }

func zfsPoolHasErrors(pool model.ZFSPool) bool { return pool.HasErrors() }

func zfsVdevHasErrors(vdevs []model.ZFSVdevError) bool {
	for _, vdev := range vdevs {
		if vdev.ReadErrors > 0 || vdev.WriteErrors > 0 || vdev.ChecksumErrors > 0 {
			return true
		}
	}
	return false
}

func zfsVdevApproximate(vdevs []model.ZFSVdevError) bool {
	return model.ZFSPool{VdevErrors: vdevs}.HasApproximateVdev()
}

// kernelPatternKinds mirrors the pattern kinds kernel.eventKind can return, so
// verbose output can show every pattern the scan looked for -- OK when a
// pattern was checked and never matched, INFO when it did -- instead of only
// ever listing the kinds that happened to fire.
var kernelPatternKinds = []string{
	"oom", "cgroup_oom", "kernel_panic", "kernel_oops", "blocked_task",
	"nvme_error", "io_error", "filesystem_corruption", "filesystem_error",
	"filesystem_readonly_remount", "hardware_error", "zfs_error", "thermal_throttling",
	"netdev_watchdog", "segfault", "link_down", "link_up", "disk_full",
}

// dnsStatus judges the resolver configuration the same way the analyzer does:
// no nameserver is a warning, and a stub-only setup is only a problem once its
// backing service has provably failed. It is duplicated in miniature here (see
// analyze.dnsFindings in backlog.go) because the renderer reports "what we
// saw" here, not a finding, for the common healthy case that produces no
// finding at all.
func dnsStatus(state *model.NetworkState, systemd *model.Systemd) (model.Severity, string) {
	if state.DNS == nil || !state.DNS.Available {
		return model.SeverityInfo, "unavailable"
	}
	dns := state.DNS
	switch {
	case len(dns.Nameservers) == 0:
		return model.SeverityWarning, "no nameserver configured"
	case dns.StubResolver && systemd != nil && systemd.Available && resolvedServiceFailed(systemd.FailedUnits):
		return model.SeverityCritical, "stub resolver configured, systemd-resolved failed"
	default:
		return model.SeverityOK, fmt.Sprintf("%d nameserver(s) configured", len(dns.Nameservers))
	}
}

func resolvedServiceFailed(failed []string) bool {
	for _, unit := range failed {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(unit)), ".service")
		if name == "systemd-resolved" {
			return true
		}
	}
	return false
}
