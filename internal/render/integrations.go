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
func renderIntegrations(w io.Writer, width int, r model.Report, separator string, color, verbose bool) {
	m := r.Metrics
	note := func(collector string) {
		if verbose {
			writeCollectionNote(w, width, r, collector, color)
		}
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
		severity := model.SeverityOK
		if unhealthy > 0 || restarting > 0 || logIssues > 0 || exited > 0 || restarts > 0 {
			severity = model.SeverityWarning
		}
		if oomKilled > 0 {
			severity = model.SeverityCritical
		}
		text := fmt.Sprintf("%s %s  %s%s%d running", sectionLabel("Containers", severity, color), badge(severity, color), cleanText(runtime.Runtime), separator, running)
		if runtime.LogsChecked > 0 {
			text += fmt.Sprintf("%slogs: %d/%d checked", separator, runtime.LogsChecked, runtime.LogCandidates)
			if runtime.LogCheckLimited {
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
		errorCount := pool.ReadErrors + pool.WriteErrors + pool.ChecksumErrors
		errorsSeverity := model.SeverityOK
		if pool.PermanentErrors {
			errorsSeverity = model.SeverityCritical
		} else if errorCount > 0 {
			errorsSeverity = model.SeverityWarning
		}
		severity := healthSeverity
		if severityRank(errorsSeverity) > severityRank(severity) {
			severity = errorsSeverity
		}
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s", sectionLabel("ZFS", severity, color), badge(severity, color), cleanText(pool.Name)))
		if verbose {
			checkLine(w, width, "    ", "Pool health", healthSeverity, color, health)
			errorsDetail := fmt.Sprintf("read %d%swrite %d%schecksum %d", pool.ReadErrors, separator, pool.WriteErrors, separator, pool.ChecksumErrors)
			if pool.PermanentErrors {
				errorsDetail += separator + "permanent errors present"
			}
			checkLine(w, width, "    ", "Data integrity", errorsSeverity, color, errorsDetail)
			scanSeverity := model.SeverityOK
			scanDetail := cleanText(pool.ScanState)
			if scanDetail == "" {
				scanDetail = "no scrub/resilver recorded"
			} else if strings.Contains(strings.ToLower(scanDetail), "in progress") {
				scanSeverity = model.SeverityInfo
			}
			checkLine(w, width, "    ", "Scrub/resilver", scanSeverity, color, scanDetail)
		} else if healthSeverity != model.SeverityOK || errorsSeverity != model.SeverityOK {
			writeWrapped(w, width, "    ", fmt.Sprintf("health %s%serrors read %d/write %d/checksum %d", health, separator, pool.ReadErrors, pool.WriteErrors, pool.ChecksumErrors))
		}
	}
	note("zfs")

	if len(m.SoftwareRAID) > 0 || m.LVM != nil || len(m.MountChecks) > 0 {
		severity := model.SeverityOK
		raidCount, raidBad := len(m.SoftwareRAID), 0
		for _, raid := range m.SoftwareRAID {
			if !strings.EqualFold(raid.State, "active") && !strings.EqualFold(raid.State, "clean") {
				raidBad++
			}
		}
		if raidBad > 0 {
			severity = model.SeverityCritical
		}
		lvmNeedsReview := false
		if m.LVM != nil {
			for _, vg := range m.LVM.VolumeGroups {
				if vg.NeedsReview {
					lvmNeedsReview = true
				}
			}
			for _, lv := range m.LVM.LogicalVolumes {
				if lv.NeedsReview {
					lvmNeedsReview = true
				}
			}
		}
		parts := []string{}
		if raidCount > 0 {
			parts = append(parts, fmt.Sprintf("RAID %d checked", raidCount))
		}
		if m.LVM != nil {
			parts = append(parts, fmt.Sprintf("LVM %d PV/%d VG/%d LV", len(m.LVM.PhysicalVolumes), len(m.LVM.VolumeGroups), len(m.LVM.LogicalVolumes)))
			if lvmNeedsReview && severityRank(model.SeverityWarning) > severityRank(severity) {
				severity = model.SeverityWarning
			}
		}
		mountsInactive := 0
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
			mountsInactive = known - active
			if known == 0 {
				parts = append(parts, fmt.Sprintf("mounts %d listed", len(m.MountChecks)))
			} else {
				parts = append(parts, fmt.Sprintf("mounts %d/%d active", active, len(m.MountChecks)))
			}
			if mountsInactive > 0 && severityRank(model.SeverityWarning) > severityRank(severity) {
				severity = model.SeverityWarning
			}
		}
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s", sectionLabel("Storage layers", severity, color), badge(severity, color), strings.Join(parts, separator)))
		if verbose {
			for _, raid := range m.SoftwareRAID {
				raidSeverity := model.SeverityOK
				if !strings.EqualFold(raid.State, "active") && !strings.EqualFold(raid.State, "clean") {
					raidSeverity = model.SeverityCritical
				}
				text := fmt.Sprintf("%s %s  %s%s%s%s%s", sectionLabel("RAID", raidSeverity, color), badge(raidSeverity, color), cleanText(raid.Device), separator, cleanText(raid.Level), separator, cleanText(raid.State))
				if raid.ResyncProgress != "" {
					text += separator + "rebuild/resync active"
				}
				writeWrapped(w, width, "    ", text)
			}
			if m.LVM != nil {
				// The collector decides what an attribute string means; reading it
				// again here is how the two interpretations drifted apart.
				lvmSeverity := model.SeverityOK
				for _, vg := range m.LVM.VolumeGroups {
					if vg.NeedsReview {
						lvmSeverity = model.SeverityWarning
					}
				}
				for _, lv := range m.LVM.LogicalVolumes {
					if lv.NeedsReview {
						lvmSeverity = model.SeverityWarning
					}
				}
				writeWrapped(w, width, "    ", fmt.Sprintf("%s %s  %d PVs%s%d VGs%s%d LVs", sectionLabel("LVM", lvmSeverity, color), badge(lvmSeverity, color), len(m.LVM.PhysicalVolumes), separator, len(m.LVM.VolumeGroups), separator, len(m.LVM.LogicalVolumes)))
			}
			if len(m.MountChecks) > 0 {
				active := 0
				for _, mount := range m.MountChecks {
					if mount.Active {
						active++
					}
				}
				mountSeverity := model.SeverityOK
				if active < len(m.MountChecks) {
					mountSeverity = model.SeverityWarning
				}
				writeWrapped(w, width, "    ", fmt.Sprintf("%s %s  persistent mounts %d/%d active", sectionLabel("Mounts", mountSeverity, color), badge(mountSeverity, color), active, len(m.MountChecks)))
				for _, mount := range m.MountChecks {
					itemSeverity := model.SeverityOK
					status := "active"
					if mount.ActiveKnown && !mount.Active {
						itemSeverity = model.SeverityWarning
						status = "not active"
					} else if !mount.ActiveKnown {
						status = "activity unknown"
					}
					detail := fmt.Sprintf("%s%s%s", cleanText(mount.FSType), separator, status)
					checkLine(w, width, "        ", cleanText(mount.MountPoint), itemSeverity, color, detail)
				}
			}
		}
	}
	note("storage")

	if len(m.DeviceHealth) > 0 {
		// Device health had no default-report row at all, so a scan that ran
		// out of time and skipped most disks looked identical to a clean sweep.
		severity := model.SeverityOK
		attention := 0
		for _, device := range m.DeviceHealth {
			if device.OverallPassed != nil && !*device.OverallPassed || device.CriticalWarning != 0 ||
				device.PendingSectors != 0 || device.Uncorrectable != 0 || device.MediaErrors != 0 {
				attention++
				severity = model.SeverityCritical
			}
		}
		text := fmt.Sprintf("%s %s  %d device(s) checked", sectionLabel("Devices", severity, color), badge(severity, color), len(m.DeviceHealth))
		if attention > 0 {
			text += fmt.Sprintf("%s%d needing attention", separator, attention)
		}
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
	note("device-health")

	if state := m.NetworkState; state != nil && state.Available {
		routes := "routes unavailable"
		if state.RoutesAvailable {
			routes = fmt.Sprintf("%d routes", len(state.Routes))
		}
		dnsSeverity, dnsText := dnsStatus(state, m.Systemd)
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  %d listening sockets%s%s%s%d connection states%sDNS: %s", sectionLabel("Network state", dnsSeverity, color), badge(dnsSeverity, color), len(state.ListeningSockets), separator, routes, separator, len(state.ConnectionStates), separator, dnsText))
		if verbose {
			dnsDetail := dnsText
			if dnsSeverity == model.SeverityOK && state.DNS != nil && len(state.DNS.Nameservers) > 0 {
				dnsDetail = "Nameservers: " + strings.Join(state.DNS.Nameservers, separator)
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
	note("network-state")

	if resolution := m.DNSResolution; resolution != nil && resolution.Available {
		localSeverity := model.SeverityOK
		if resolution.Local != nil {
			localSeverity = findingSeverity(r.Findings, "dns-resolution-failed", "dns-resolution-local-failed")
		}
		externalSeverity := findingSeverity(r.Findings, "dns-resolution-failed", "dns-resolution-external-failed")
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
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  local: %s%sexternal: %s", sectionLabel("DNS resolution", severity, color), badge(severity, color), summary(resolution.Local), separator, summary(resolution.External)))
		if verbose {
			detail := func(result *model.DNSResolutionResult) string {
				if result == nil {
					return "no local nameserver configured"
				}
				if result.Resolved {
					return fmt.Sprintf("resolved %s via %s in %.0fms", result.Domain, result.Server, result.LatencyMillis)
				}
				return fmt.Sprintf("failed to resolve %s via %s: %s", result.Domain, result.Server, result.Error)
			}
			checkLine(w, width, "    ", "Local resolution", localSeverity, color, detail(resolution.Local))
			checkLine(w, width, "    ", "External resolution", externalSeverity, color, detail(resolution.External))
		}
	}
	note("dns-resolution")

	if check := m.GatewayCheck; check != nil && check.Available {
		severity := findingSeverity(r.Findings, "gateway-unreachable", "gateway-packet-loss")
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s%s%d/%d replies%s%.0f%% loss", sectionLabel("Gateway", severity, color), badge(severity, color), cleanText(check.Gateway), separator, check.Received, check.Sent, separator, check.PacketLossPct))
		if verbose && check.Received > 0 {
			checkLine(w, width, "    ", "Latency", model.SeverityOK, color, fmt.Sprintf("%.1fms average", check.AvgLatencyMillis))
		}
	}
	note("gateway-ping")

	if check := m.PathMTUCheck; check != nil && check.Available {
		severity := findingSeverity(r.Findings, "path-mtu-blackhole", "path-mtu-reduced")
		result := fmt.Sprintf("%d/%d bytes usable", check.CeilingMTU, check.CeilingMTU)
		switch {
		case check.DiscoveredMTU == 0:
			result = fmt.Sprintf("no packet size got through down to %d bytes (possible black hole)", check.FloorMTU)
		case check.DiscoveredMTU < check.CeilingMTU:
			result = fmt.Sprintf("%d/%d bytes usable (reduced but working normally, typical for a VPN or tunnel)", check.DiscoveredMTU, check.CeilingMTU)
		}
		// A reduced-but-discovered MTU is common and expected (PPPoE, VPNs,
		// tunnels); showing that INFO badge on every run is noise for a
		// permanent, intentional configuration, so it is quiet by default
		// and stays available under --verbose. OK and WARN/CRIT rows still
		// always show, consistent with every other active check.
		if verbose || severity != model.SeverityInfo {
			writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s%s%s", sectionLabel("Path MTU", severity, color), badge(severity, color), cleanText(check.Target), separator, result))
		}
		if verbose {
			checkLine(w, width, "    ", "Baseline (small packet)", model.SeverityOK, color, "reachable")
			mtuSeverity := model.SeverityOK
			mtuDetail := fmt.Sprintf("%d bytes, the full tested ceiling", check.DiscoveredMTU)
			switch {
			case check.DiscoveredMTU == 0:
				mtuSeverity = severity
				mtuDetail = fmt.Sprintf("none found; every size from %d down to %d bytes was dropped", check.CeilingMTU, check.FloorMTU)
			case check.DiscoveredMTU < check.CeilingMTU:
				mtuSeverity = severity
				mtuDetail = fmt.Sprintf("%d bytes -- below the %d-byte ceiling, but a working, cleanly discovered size (PMTUD is functioning correctly)", check.DiscoveredMTU, check.CeilingMTU)
			}
			checkLine(w, width, "    ", "Discovered path MTU", mtuSeverity, color, mtuDetail)
		}
	}
	note("path-mtu")

	if check := m.HTTPCheck; check != nil && check.Available {
		httpSeverity := findingSeverity(r.Findings, "http-check-failed", "http-check-http-failed")
		httpsSeverity := findingSeverity(r.Findings, "http-check-failed", "https-check-failed")
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
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  http: %s%shttps: %s", sectionLabel("HTTP checks", severity, color), badge(severity, color), summary(check.HTTP), separator, summary(check.HTTPS)))
		if verbose {
			detail := func(result *model.HTTPCheckResult) string {
				if result == nil {
					return "not attempted"
				}
				if result.Succeeded {
					return fmt.Sprintf("%s -> %d in %.0fms", result.URL, result.StatusCode, result.LatencyMillis)
				}
				return fmt.Sprintf("%s failed: %s", result.URL, result.Error)
			}
			checkLine(w, width, "    ", "HTTP", httpSeverity, color, detail(check.HTTP))
			checkLine(w, width, "    ", "HTTPS", httpsSeverity, color, detail(check.HTTPS))
		}
	}
	note("http-check")

	if check := m.ICMPCheck; check != nil && check.Available {
		severity := findingSeverity(r.Findings, "icmp-external-unreachable", "icmp-external-packet-loss", "icmp-external-high-latency")
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s%s%d/%d replies%s%.0f%% loss", sectionLabel("External ICMP", severity, color), badge(severity, color), cleanText(check.Target), separator, check.Received, check.Sent, separator, check.PacketLossPct))
		if verbose && check.Received > 0 {
			checkLine(w, width, "    ", "Latency", model.SeverityOK, color, fmt.Sprintf("%.1fms average", check.AvgLatencyMillis))
		}
	}
	note("icmp-check")

	if check := m.IPv6Check; check != nil && check.Available {
		severity := findingSeverity(r.Findings, "ipv6-unreachable", "ipv6-packet-loss")
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s%s%d/%d replies%s%.0f%% loss", sectionLabel("IPv6", severity, color), badge(severity, color), cleanText(check.Target), separator, check.Received, check.Sent, separator, check.PacketLossPct))
		if verbose && check.Received > 0 {
			checkLine(w, width, "    ", "Latency", model.SeverityOK, color, fmt.Sprintf("%.1fms average", check.AvgLatencyMillis))
		}
	}
	note("ipv6-check")

	if df := m.DeletedFiles; df != nil && df.Available {
		severity := findingSeverity(r.Findings, "deleted-files-open")
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  %s across %d unique file(s)%s%d process(es) holding", sectionLabel("Deleted files", severity, color), badge(severity, color), size(df.TotalBytes), df.UniqueFiles, separator, df.ProcessesHolding))
		if verbose {
			checkLine(w, width, "    ", "Coverage", model.SeverityOK, color, fmt.Sprintf("%d process(es) scanned%s%d skipped (permission)%s%d total reference(s)", df.ProcessesScanned, separator, df.ProcessesSkipped, separator, df.TotalReferences))
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
				checkLine(w, width, "    ", fmt.Sprintf("dev %s inode %d", f.Device, f.Inode), severity, color, detail)
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
	note("hardware-errors")

	if k := m.Kernel; k != nil && k.Available {
		severity := model.SeverityOK
		if len(k.Events) > 0 {
			severity = model.SeverityInfo
		}
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  %d pattern match(es) in kernel log", sectionLabel("Kernel", severity, color), badge(severity, color), len(k.Events)))
		if verbose {
			counts := make(map[string]int, len(k.Events))
			for _, event := range k.Events {
				counts[event.Kind]++
			}
			for _, kind := range kernelPatternKinds {
				count := counts[kind]
				delete(counts, kind)
				lineSeverity := model.SeverityOK
				detail := "no matches"
				if count > 0 {
					lineSeverity = model.SeverityInfo
					detail = fmt.Sprintf("%d match(es)", count)
				}
				checkLine(w, width, "    ", strings.ReplaceAll(kind, "_", " "), lineSeverity, color, detail)
			}
			// Any kind the collector reports that this renderer does not yet
			// know about still needs to be visible rather than silently dropped.
			unknown := make([]string, 0, len(counts))
			for kind := range counts {
				unknown = append(unknown, kind)
			}
			sort.Strings(unknown)
			for _, kind := range unknown {
				checkLine(w, width, "    ", strings.ReplaceAll(kind, "_", " "), model.SeverityInfo, color, fmt.Sprintf("%d match(es)", counts[kind]))
			}
		}
	}
	note("kernel")

	if security := m.Security; security != nil && security.Available {
		severity := model.SeverityOK
		if security.SELinuxDenials != nil && *security.SELinuxDenials > 0 || security.AppArmorDenials != nil && *security.AppArmorDenials > 0 {
			severity = model.SeverityWarning
		}
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  SELinux %s%sAppArmor %s%ssecurity sources checked", sectionLabel("Security", severity, color), badge(severity, color), cleanText(security.SELinux), separator, cleanText(security.AppArmor), separator))
		if verbose {
			selinuxSeverity := model.SeverityOK
			if security.SELinuxDenials != nil && *security.SELinuxDenials > 0 {
				selinuxSeverity = model.SeverityWarning
			}
			selinuxDetail := cleanText(security.SELinux)
			if security.SELinuxDenials != nil {
				selinuxDetail += fmt.Sprintf("%s%d denial(s)", separator, *security.SELinuxDenials)
			}
			checkLine(w, width, "    ", "SELinux", selinuxSeverity, color, selinuxDetail)

			apparmorSeverity := model.SeverityOK
			if security.AppArmorDenials != nil && *security.AppArmorDenials > 0 {
				apparmorSeverity = model.SeverityWarning
			}
			apparmorDetail := cleanText(security.AppArmor)
			if security.AppArmorDenials != nil {
				apparmorDetail += fmt.Sprintf("%s%d denial(s)", separator, *security.AppArmorDenials)
			}
			checkLine(w, width, "    ", "AppArmor", apparmorSeverity, color, apparmorDetail)

			if security.ActiveSessions != nil {
				checkLine(w, width, "    ", "Active sessions", model.SeverityOK, color, fmt.Sprintf("%d", *security.ActiveSessions))
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
		}
	}
	note("security")

	if cgroup := m.CgroupV2; cgroup != nil && cgroup.Available {
		writeWrapped(w, width, "", fmt.Sprintf("%s %s  containerized: %t", sectionLabel("Cgroup v2", model.SeverityOK, color), badge(model.SeverityOK, color), cgroup.Containerized))
		if verbose {
			checkLine(w, width, "    ", "Path", model.SeverityOK, color, cleanText(cgroup.Path))
			if cgroup.MemoryMaxBytes != nil && *cgroup.MemoryMaxBytes > 0 {
				fraction := float64(cgroup.MemoryCurrentBytes) * 100 / float64(*cgroup.MemoryMaxBytes)
				memSeverity := model.SeverityOK
				if fraction >= 95 {
					memSeverity = model.SeverityWarning
				}
				checkLine(w, width, "    ", "Memory limit", memSeverity, color, fmt.Sprintf("%.0f%% used", fraction))
			} else {
				checkLine(w, width, "    ", "Memory limit", model.SeverityOK, color, "none set")
			}
			if cgroup.PIDsMax != nil && *cgroup.PIDsMax > 0 {
				fraction := float64(cgroup.PIDsCurrent) * 100 / float64(*cgroup.PIDsMax)
				pidSeverity := model.SeverityOK
				if fraction >= 95 {
					pidSeverity = model.SeverityWarning
				}
				checkLine(w, width, "    ", "PID limit", pidSeverity, color, fmt.Sprintf("%d/%d", cgroup.PIDsCurrent, *cgroup.PIDsMax))
			} else {
				checkLine(w, width, "    ", "PID limit", model.SeverityOK, color, "none set")
			}
		}
	}
	note("cgroup-v2")
}

// kernelPatternKinds mirrors the pattern kinds kernel.eventKind can return, so
// verbose output can show every pattern the scan looked for -- OK when a
// pattern was checked and never matched, INFO when it did -- instead of only
// ever listing the kinds that happened to fire.
var kernelPatternKinds = []string{
	"oom", "cgroup_oom", "kernel_panic", "kernel_oops", "blocked_task",
	"nvme_error", "io_error", "filesystem_corruption", "filesystem_error",
	"hardware_error", "zfs_error", "thermal_throttling",
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
