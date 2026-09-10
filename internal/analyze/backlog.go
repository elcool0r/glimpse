package analyze

import (
	"fmt"
	"strings"

	"github.com/elcool0r/glimpse/internal/model"
)

func backlogFindings(report *model.Report) []model.Finding {
	var findings []model.Finding
	findings = append(findings, memoryBacklogFindings(report.Metrics.Memory, report.Metrics.Pressure)...)
	findings = append(findings, storageBacklogFindings(report.Metrics.SoftwareRAID, report.Metrics.LVM, report.Metrics.MountChecks)...)
	findings = append(findings, securityBacklogFindings(report.Metrics.Security)...)
	findings = append(findings, networkStateFindings(report.Metrics.NetworkState)...)
	findings = append(findings, dnsFindings(report.Metrics.NetworkState, report.Metrics.Systemd)...)
	findings = append(findings, dnsResolutionFindings(report.Metrics.DNSResolution)...)
	findings = append(findings, gatewayFindings(report.Metrics.GatewayCheck)...)
	findings = append(findings, pathMTUFindings(report.Metrics.PathMTUCheck)...)
	findings = append(findings, httpCheckFindings(report.Metrics.HTTPCheck)...)
	findings = append(findings, icmpCheckFindings(report.Metrics.ICMPCheck)...)
	findings = append(findings, ipv6CheckFindings(report.Metrics.IPv6Check)...)
	findings = append(findings, deletedFilesFindings(report.Metrics.DeletedFiles)...)
	findings = append(findings, hardwareErrorFindings(report.Metrics.Hardware)...)
	return findings
}

func memoryBacklogFindings(memory *model.Memory, pressure *model.Pressure) []model.Finding {
	if memory == nil {
		return nil
	}
	var findings []model.Finding
	if memoryAvailable(memory) && memory.Swappiness != nil && *memory.Swappiness >= 80 && memory.AvailableFraction < .10 && (memory.SwapInBytes > 0 || pressure != nil && pressure.Memory.SomeAvg10 >= 1) {
		findings = append(findings, finding("memory-swappiness", model.SeverityInfo, "memory", "High swappiness during memory pressure", fmt.Sprintf("vm.swappiness is %d while MemAvailable is %.1f%% and swap or memory pressure was observed.", *memory.Swappiness, memory.AvailableFraction*100), "Review swappiness alongside workload latency and memory policy before changing it.", 0))
	}
	if memoryAvailable(memory) && memory.PageFaults >= 100000 && memory.MajorFaults >= 1000 && memory.AvailableFraction < .15 {
		cmd := "ps aux --sort=-%mem | head -11 && vmstat 1 3 | tail -2"
		findings = append(findings, findingWithDiagnostic("memory-fault-pressure", model.SeverityWarning, "memory", "Memory fault pressure observed", fmt.Sprintf("The sample recorded %d page faults and %d major faults while only %.1f%% of memory was available.", memory.PageFaults, memory.MajorFaults, memory.AvailableFraction*100), "Inspect memory pressure, swap activity, and the largest memory consumers.", cmd, 8))
	}
	return findings
}

func storageBacklogFindings(raids []model.SoftwareRAID, lvm *model.LVM, mounts []model.MountCheck) []model.Finding {
	var findings []model.Finding
	for _, raid := range raids {
		state := strings.ToLower(strings.TrimSpace(raid.State))
		if state != "active" && state != "clean" {
			findings = append(findings, findingWithDiagnostic("raid-"+raid.Device, model.SeverityCritical, "storage", "Software RAID is degraded", fmt.Sprintf("%s reports state %s.", raid.Device, raid.State), "Inspect /proc/mdstat and repair or replace the affected member devices.", "cat /proc/mdstat", 25))
		} else if raid.ResyncProgress != "" {
			findings = append(findings, finding("raid-resync-"+raid.Device, model.SeverityInfo, "storage", "Software RAID is rebuilding", fmt.Sprintf("%s has an active recovery or resync operation.", raid.Device), "Allow the rebuild to finish and verify the array returns to a clean state.", 0))
		}
	}
	if lvm != nil {
		// The collector interprets the positional attribute bits; analysis and
		// rendering both read its verdict, so there is one reading of them.
		for _, vg := range lvm.VolumeGroups {
			if vg.NeedsReview {
				cmd := fmt.Sprintf("vgs -a %s 2>/dev/null", vg.Name)
				findings = append(findings, findingWithDiagnostic("lvm-vg-"+vg.Name, model.SeverityWarning, "storage", "LVM volume group needs review", fmt.Sprintf("Volume group %s is %s (attributes %q).", vg.Name, vg.ReviewReason, vg.Attr), "Inspect the volume group with vgs and verify it is writable and complete.", cmd, 12))
			}
		}
		for _, lv := range lvm.LogicalVolumes {
			if lv.NeedsReview {
				cmd := fmt.Sprintf("lvs -a %s/%s 2>/dev/null", lv.Group, lv.Name)
				findings = append(findings, findingWithDiagnostic("lvm-lv-"+lv.Group+"-"+lv.Name, model.SeverityWarning, "storage", "LVM logical volume needs review", fmt.Sprintf("Logical volume %s/%s is %s (attributes %q).", lv.Group, lv.Name, lv.ReviewReason, lv.Attr), "Inspect the logical volume with lvs and verify it is active and complete.", cmd, 12))
			}
		}
	}
	for _, mount := range mounts {
		if !mount.ActiveKnown || mount.Active || mountHasOption(mount, "nofail") || mountHasOption(mount, "noauto") {
			continue
		}
		cmd := fmt.Sprintf("cat /etc/fstab | grep %s && lsblk", mount.MountPoint)
		findings = append(findings, findingWithDiagnostic("mount-missing-"+mount.MountPoint, model.SeverityWarning, "storage", "Persistent mount is unavailable", fmt.Sprintf("%s is listed in /etc/fstab but is not currently mounted.", mount.MountPoint), "Verify the device, filesystem, and intended mount policy before mounting it.", cmd, 10))
	}
	return findings
}

func mountHasOption(m model.MountCheck, want string) bool {
	for _, option := range m.Options {
		if strings.EqualFold(strings.TrimSpace(option), want) {
			return true
		}
	}
	return false
}

func securityBacklogFindings(s *model.Security) []model.Finding {
	if s == nil {
		return nil
	}
	var findings []model.Finding
	window := s.JournalWindow
	if window == "" {
		window = "the recent journal window"
	} else {
		window = "the last " + window
	}
	if s.FailedAuthAttempts != nil && *s.FailedAuthAttempts > 0 {
		// Any host reachable from the internet accumulates failed passwords
		// continuously; a handful is background noise, not an incident. Only a
		// sustained rate within the measured window warrants a warning.
		severity, impact := model.SeverityInfo, 0
		if *s.FailedAuthAttempts >= failedAuthWarning {
			severity, impact = model.SeverityWarning, 8
		}
		cmd := "journalctl SYSLOG_IDENTIFIER=sshd PRIORITY=3..5 --since '24 hours ago' 2>/dev/null | grep -E 'Invalid|Failed|Denied'"
		findings = append(findings, findingWithDiagnostic("security-failed-auth", severity, "security", "Failed authentication attempts", fmt.Sprintf("The authentication journal for %s contains %d failed authentication event(s).", window, *s.FailedAuthAttempts), "Review source addresses, exposed services, and authentication policy in the system journal.", cmd, impact))
	}
	if s.SELinuxDenials != nil && *s.SELinuxDenials > 0 {
		cmd := "journalctl --since '24 hours ago' 2>/dev/null | grep -i 'selinux.*denied'"
		findings = append(findings, findingWithDiagnostic("security-selinux-denials", model.SeverityWarning, "security", "SELinux denials observed", fmt.Sprintf("The kernel journal for %s contains %d SELinux denial event(s).", window, *s.SELinuxDenials), "Review the denied operation and policy before changing enforcement mode.", cmd, 8))
	}
	if s.AppArmorDenials != nil && *s.AppArmorDenials > 0 {
		cmd := "journalctl --since '24 hours ago' 2>/dev/null | grep -i 'apparmor.*denied'"
		findings = append(findings, findingWithDiagnostic("security-apparmor-denials", model.SeverityWarning, "security", "AppArmor denials observed", fmt.Sprintf("The kernel journal for %s contains %d AppArmor denial event(s).", window, *s.AppArmorDenials), "Review the affected profile and denied operation before changing policy.", cmd, 8))
	}
	if s.CoreDumps != nil && *s.CoreDumps > 0 {
		cmd := "coredumpctl list --since '24 hours ago' 2>/dev/null"
		findings = append(findings, findingWithDiagnostic("security-core-dumps", model.SeverityWarning, "security", "Recent core dumps found", fmt.Sprintf("The recent crash window contains %d core dump(s).", *s.CoreDumps), "Inspect coredumpctl and the affected service stack for the root cause.", cmd, 10))
	}
	if len(s.CrashArtifacts) > 0 {
		// /var/crash is an unbounded directory that nothing clears on its own.
		// Its contents are historical evidence, like the cumulative EDAC
		// counters, and are reported the same way: informational, no score
		// impact. A crash inside the measured window is reported by
		// coredumpctl above.
		findings = append(findings, findingWithDiagnostic("security-crash-artifacts", model.SeverityInfo, "security", "Crash artifacts present", fmt.Sprintf("The crash directory contains %d artifact(s); this directory is not cleared automatically, so entries may be old.", len(s.CrashArtifacts)), "Review the artifacts and clear them only after preserving evidence needed for diagnosis.", "sudo ls -lah /var/crash", 0))
	}
	return findings
}

func networkStateFindings(state *model.NetworkState) []model.Finding {
	if state == nil || !state.Available || !state.RoutesAvailable {
		return nil
	}
	for _, route := range state.Routes {
		if route.Destination == "default" || route.Destination == "0.0.0.0/0" || route.Destination == "::/0" {
			return nil
		}
	}
	return []model.Finding{finding("network-no-default-route", model.SeverityInfo, "network", "No default route observed", "The local routing table contains no default route.", "Confirm that this host is intentionally isolated or add the expected default route.", 0)}
}

// dnsFindings judges the resolver configuration as written. It never sends a
// query, so it reports only the two faults that are visible from the file and
// from state already collected. dnsResolutionFindings below covers whether
// resolution actually works, when the user opted into that active probe.
func dnsFindings(state *model.NetworkState, systemd *model.Systemd) []model.Finding {
	if state == nil || state.DNS == nil || !state.DNS.Available {
		return nil
	}
	dns := state.DNS
	if len(dns.Nameservers) == 0 {
		cmd := "cat /etc/resolv.conf && resolvectl status 2>/dev/null | head -10"
		return []model.Finding{findingWithDiagnostic("dns-no-nameserver", model.SeverityWarning, "network", "No DNS nameserver configured",
			"The resolver configuration lists no nameserver, so name resolution can only use static entries.",
			"Confirm that this host resolves names through /etc/hosts by design, or restore the expected nameserver configuration.", cmd, 12)}
	}
	// Pointing only at the stub delegates all resolution to systemd-resolved.
	// That is a normal arrangement on its own, so it is reported only when the
	// service it depends on has actually failed -- then DNS is provably broken
	// rather than merely dependent.
	if dns.StubResolver && systemd != nil && systemd.Available && resolvedFailed(systemd.FailedUnits) {
		cmd := "systemctl status systemd-resolved && resolvectl status 2>/dev/null"
		return []model.Finding{findingWithDiagnostic("dns-stub-resolver-failed", model.SeverityCritical, "network", "DNS stub resolver is configured but its service failed",
			"Every configured nameserver is the local systemd-resolved stub, and systemd-resolved is in a failed state.",
			"Inspect systemd-resolved and restart it; until it runs, this host cannot resolve names.", cmd, 20)}
	}
	return nil
}

// dnsResolutionFindings judges the active probe: the external checks send a
// real query to the local nameserver and to 1.1.1.1 (--disable-external-checks
// turns this off). Losing the external resolver while the local one still
// answers means this host cannot resolve names anywhere on the public
// internet, which is treated as critical; losing the local resolver, or
// losing both, is reported accordingly.
func dnsResolutionFindings(resolution *model.DNSResolution) []model.Finding {
	if resolution == nil || !resolution.Available {
		return nil
	}
	localAttempted := resolution.Local != nil
	localOK := localAttempted && resolution.Local.Resolved
	externalAttempted := resolution.External != nil
	externalOK := externalAttempted && resolution.External.Resolved

	switch {
	case externalAttempted && !externalOK && (!localAttempted || !localOK):
		// No configured nameserver resolved anything, and neither did the
		// external resolver: the host cannot resolve names at all right now.
		detail := fmt.Sprintf("Resolving %s against the external resolver (%s) failed.", resolution.External.Domain, resolution.External.Server)
		if localAttempted {
			detail = fmt.Sprintf("Resolving %s failed against both the local nameserver (%s) and the external resolver (%s).", resolution.Local.Domain, resolution.Local.Server, resolution.External.Server)
		}
		cmd := fmt.Sprintf("dig @%s %s +short || getent hosts %s", resolution.External.Server, resolution.External.Domain, resolution.External.Domain)
		return []model.Finding{findingWithDiagnostic("dns-resolution-failed", model.SeverityCritical, "network", "DNS resolution is not working",
			detail, "Inspect the resolver configuration, local DNS service, and network path to any DNS server.", cmd, 25)}
	case localAttempted && !localOK:
		cmd := fmt.Sprintf("dig @%s %s +short", resolution.Local.Server, resolution.Local.Domain)
		return []model.Finding{findingWithDiagnostic("dns-resolution-local-failed", model.SeverityWarning, "network", "Local DNS server is not resolving names",
			fmt.Sprintf("Resolving %s against the configured nameserver (%s) failed, but the same query succeeded against %s.", resolution.Local.Domain, resolution.Local.Server, resolution.External.Server),
			"Inspect the local DNS server or forwarder; clients depending on it cannot resolve names.", cmd, 15)}
	case externalAttempted && !externalOK:
		cmd := fmt.Sprintf("dig @%s %s +short", resolution.External.Server, resolution.External.Domain)
		return []model.Finding{findingWithDiagnostic("dns-resolution-external-failed", model.SeverityInfo, "network", "External DNS server unreachable",
			fmt.Sprintf("Resolving %s against %s failed, though the configured nameserver resolves it. This tests direct DNS access to that external resolver only.", resolution.External.Domain, resolution.External.Server),
			"Confirm whether direct DNS to this resolver is intentionally restricted; if not, inspect the network path and firewall rules for UDP/TCP 53.", cmd, 0)}
	}
	return dnsLatencyFindings(resolution)
}

// dnsLatencyWarningMillis and dnsLatencyCriticalMillis catch "DNS works but
// applications pause for seconds" -- resolution that succeeds but is slow
// enough to be felt, distinct from the resolution-failed findings above,
// which never look at latency. A resolver on the same LAN or a healthy
// anycast service normally answers in single-digit to low-double-digit
// milliseconds, so even the warning threshold is well above ordinary
// variance.
const (
	dnsLatencyWarningMillis  = 1000.0
	dnsLatencyCriticalMillis = 3000.0
)

func dnsLatencyFindings(resolution *model.DNSResolution) []model.Finding {
	var findings []model.Finding
	for _, named := range []struct {
		id     string
		label  string
		result *model.DNSResolutionResult
	}{
		{"dns-resolution-local-slow", "local", resolution.Local},
		{"dns-resolution-external-slow", "external", resolution.External},
	} {
		result := named.result
		if result == nil || !result.Resolved || result.LatencyMillis < dnsLatencyWarningMillis {
			continue
		}
		severity, impact := model.SeverityWarning, 6
		if result.LatencyMillis >= dnsLatencyCriticalMillis {
			severity, impact = model.SeverityCritical, 12
		}
		findings = append(findings, finding(named.id, severity, "network", fmt.Sprintf("Slow %s DNS resolution", named.label),
			fmt.Sprintf("Resolving %s against %s succeeded but took %.0f ms.", result.Domain, result.Server, result.LatencyMillis),
			"Inspect the resolver's load, network path latency, and whether a faster resolver is available; applications will pause for this long on every uncached lookup.", impact))
	}
	return findings
}

// gatewayFindings judges the active gateway probe. No reply at all means
// nothing off-link is reachable; partial loss is reported only past a
// majority threshold so an occasional dropped ping on a healthy link does not
// warn.
// gatewayLatencyWarningMillis and gatewayLatencyCriticalMillis are deliberately
// strict: the default gateway is normally on the same local network segment,
// where round-trip time is expected in the low single-digit milliseconds
// even over a loaded home network. Triple-digit latency there is a real,
// unusual fault (a saturated link, a misbehaving switch, traffic shaping) and
// not a normal condition to filter out.
const (
	gatewayLatencyWarningMillis  = 200.0
	gatewayLatencyCriticalMillis = 500.0
)

func gatewayFindings(check *model.GatewayCheck) []model.Finding {
	if check == nil || !check.Available || check.Sent == 0 {
		return nil
	}
	if check.Received == 0 {
		cmd := fmt.Sprintf("ip route show | grep default && ping -c 5 %s", check.Gateway)
		return []model.Finding{findingWithDiagnostic("gateway-unreachable", model.SeverityCritical, "network", "Default gateway is not responding",
			fmt.Sprintf("All %d ICMP echo requests to the default gateway (%s) went unanswered.", check.Sent, check.Gateway),
			"Inspect the local network link, switch/router, and default gateway configuration.", cmd, 20)}
	}
	var findings []model.Finding
	if check.PacketLossPct >= 50 {
		cmd := fmt.Sprintf("mtr -c 10 %s 2>/dev/null || ping -c 10 %s", check.Gateway, check.Gateway)
		findings = append(findings, findingWithDiagnostic("gateway-packet-loss", model.SeverityWarning, "network", "Default gateway is dropping pings",
			fmt.Sprintf("%.0f%% of ICMP echo requests to the default gateway (%s) were lost (%d of %d).", check.PacketLossPct, check.Gateway, check.Sent-check.Received, check.Sent),
			"Inspect the local network link and gateway health.", cmd, 10))
	}
	if check.AvgLatencyMillis >= gatewayLatencyWarningMillis {
		severity, impact := model.SeverityWarning, 8
		if check.AvgLatencyMillis >= gatewayLatencyCriticalMillis {
			severity, impact = model.SeverityCritical, 15
		}
		cmd := fmt.Sprintf("ping -c 5 %s && mtr -c 10 %s 2>/dev/null", check.Gateway, check.Gateway)
		findings = append(findings, findingWithDiagnostic("gateway-high-latency", severity, "network", "Default gateway latency is elevated",
			fmt.Sprintf("Average round-trip time to the default gateway (%s) was %.0f ms during the sample; a local, same-segment gateway is normally single-digit milliseconds.", check.Gateway, check.AvgLatencyMillis),
			"Inspect local link saturation, duplex/speed mismatches, and traffic shaping on the path to the gateway.", cmd, impact))
	}
	return findings
}

// pathMTUFindings reports only the observations made by the bounded IPv4 DF
// probe series. A dropped baseline ping means the anchor
// host is unreachable right now, which the gateway and DNS checks already
// speak to -- it says nothing about MTU specifically, so it produces no
// finding here. A reply below the tested ceiling with packet-too-big feedback
// is a successful PMTU observation: the path communicated its smaller limit,
// so it does not merit an informational finding. Without that feedback, the
// reduced reply remains informational. Receiving no replies across the series
// remains a warning.
func pathMTUFindings(check *model.PathMTUCheck) []model.Finding {
	if check == nil || !check.Available || !check.BaselineOK {
		return nil
	}
	if check.DiscoveredMTU == 0 {
		feedback := "No packet-too-big feedback was observed in the probe output."
		if check.PacketTooBigFeedback {
			feedback = "Packet-too-big feedback was observed in the probe output."
		}
		return []model.Finding{finding("path-mtu-blackhole", model.SeverityWarning, "network", "No IPv4 DF echo replies across tested sizes",
			fmt.Sprintf("The baseline ping to %s replied, but IPv4 DF probes from %d down to %d bytes received no echo replies. %s", check.Target, check.CeilingMTU, check.FloorMTU, feedback),
			"Inspect VPN, tunnel, middlebox, and ICMP handling if large transfers over this path stall while smaller packets succeed.", 12)}
	}
	if check.DiscoveredMTU < check.CeilingMTU {
		if check.PacketTooBigFeedback {
			return nil
		}
		return []model.Finding{finding("path-mtu-reduced", model.SeverityInfo, "network", fmt.Sprintf("Largest tested IPv4 DF echo reply was %d bytes", check.DiscoveredMTU),
			fmt.Sprintf("The %d-byte IPv4 DF probe to %s replied after larger tested sizes up to %d bytes did not reply.", check.DiscoveredMTU, check.Target, check.CeilingMTU),
			"Compare this observation with VPN, tunnel, and interface settings if large transfers over this path stall.", 0)}
	}
	return nil
}

// httpCheckFindings judges the outbound web probe: one protocol failing
// while the other succeeds is a warning (a firewall rule or proxy scoped to
// one port, or TLS interception on 443 specifically); both failing is
// critical, matching the external-only DNS resolution failure treatment.
func httpCheckFindings(check *model.HTTPCheck) []model.Finding {
	if check == nil || !check.Available {
		return nil
	}
	var findings []model.Finding
	if check.HTTP != nil && check.HTTP.ProxyUsed || check.HTTPS != nil && check.HTTPS.ProxyUsed {
		findings = append(findings, finding("http-check-proxy-used", model.SeverityInfo, "network", "HTTP checks used an environment proxy",
			"At least one HTTP connectivity probe used the proxy selected by HTTP_PROXY, HTTPS_PROXY, or NO_PROXY.",
			"No action needed; run with --no-proxy to test direct HTTP connectivity instead.", 0))
	}
	httpFailed := check.HTTP != nil && !check.HTTP.Succeeded
	httpsFailed := check.HTTPS != nil && !check.HTTPS.Succeeded
	switch {
	case httpFailed && httpsFailed:
		cmd := fmt.Sprintf("curl -Iv %s && curl -Iv %s", check.HTTP.URL, check.HTTPS.URL)
		findings = append(findings, findingWithDiagnostic("http-check-failed", model.SeverityWarning, "network", "HTTP and HTTPS requests are both failing",
			fmt.Sprintf("A GET to %s failed (%s) and a GET to %s failed (%s).", check.HTTP.URL, check.HTTP.Error, check.HTTPS.URL, check.HTTPS.Error),
			"Confirm proxy policy and reachability, or inspect firewall and routing policy for direct checks.", cmd, 8))
	case httpsFailed:
		cmd := fmt.Sprintf("curl -Iv %s", check.HTTPS.URL)
		findings = append(findings, findingWithDiagnostic("https-check-failed", model.SeverityWarning, "network", "HTTPS request failed while HTTP succeeded",
			fmt.Sprintf("A GET to %s failed: %s", check.HTTPS.URL, check.HTTPS.Error),
			"Inspect TLS interception, certificate trust, or firewalling of port 443 specifically.", cmd, 8))
	case httpFailed:
		cmd := fmt.Sprintf("curl -Iv %s", check.HTTP.URL)
		findings = append(findings, findingWithDiagnostic("http-check-http-failed", model.SeverityWarning, "network", "HTTP request failed while HTTPS succeeded",
			fmt.Sprintf("A GET to %s failed: %s", check.HTTP.URL, check.HTTP.Error),
			"This is unusual since HTTPS succeeded; inspect port 80 filtering specifically.", cmd, 8))
	}
	return findings
}

// externalLatencyWarningMillis and externalLatencyCriticalMillis are looser
// than the gateway thresholds: 1.1.1.1 is anycast with points of presence in
// most regions, but real, healthy round trips still vary far more than a
// same-segment gateway does depending on the user's own location and access
// network. These stay conservative enough to avoid warning on ordinary
// broadband or a distant-but-working path, while still catching a gross
// degradation like a saturated link or heavy shaping.
const (
	externalLatencyWarningMillis  = 300.0
	externalLatencyCriticalMillis = 800.0
)

// icmpCheckFindings judges the external ICMP probe. No reply at all means
// this host cannot reach anything beyond its own gateway over ICMP, which a
// healthy gateway-only check cannot see; partial loss and elevated latency
// are judged the same way the gateway check judges its own probe.
func icmpCheckFindings(check *model.ICMPCheck) []model.Finding {
	if check == nil || !check.Available || check.Sent == 0 {
		return nil
	}
	if check.Received == 0 {
		return []model.Finding{finding("icmp-external-unreachable", model.SeverityInfo, "network", "External ICMP probe received no replies",
			fmt.Sprintf("All %d ICMP echo requests to %s went unanswered. This tests ICMP reachability to that target only.", check.Sent, check.Target),
			"Confirm whether ICMP is intentionally filtered; correlate with DNS or HTTP checks before diagnosing broader connectivity.", 0)}
	}
	var findings []model.Finding
	if check.PacketLossPct >= 50 {
		findings = append(findings, finding("icmp-external-packet-loss", model.SeverityWarning, "network", "External ICMP packets are being dropped",
			fmt.Sprintf("%.0f%% of ICMP echo requests to %s were lost (%d of %d).", check.PacketLossPct, check.Target, check.Sent-check.Received, check.Sent),
			"Inspect the upstream network path for congestion or filtering.", 10))
	}
	if check.AvgLatencyMillis >= externalLatencyWarningMillis {
		severity, impact := model.SeverityWarning, 8
		if check.AvgLatencyMillis >= externalLatencyCriticalMillis {
			severity, impact = model.SeverityCritical, 15
		}
		findings = append(findings, finding("icmp-external-high-latency", severity, "network", "External network latency is elevated",
			fmt.Sprintf("Average round-trip time to %s was %.0f ms during the sample.", check.Target, check.AvgLatencyMillis),
			"Inspect upstream link saturation and traffic shaping; a persistently high round trip degrades every network-dependent service.", impact))
	}
	return findings
}

// ipv6CheckFindings judges the external IPv6 probe. It only ever runs (see
// internal/collect/ipv6check) when the host has a global IPv6 address
// configured, so reaching this function at all means the host believes it
// has working IPv6 -- an IPv4-only host never produces a check to judge.
func ipv6CheckFindings(check *model.IPv6Check) []model.Finding {
	if check == nil || !check.Available || check.Sent == 0 {
		return nil
	}
	if check.Received == 0 {
		return []model.Finding{finding("ipv6-unreachable", model.SeverityWarning, "network", "IPv6 ICMP probe received no replies",
			fmt.Sprintf("This host has a global IPv6 address, but all %d ICMPv6 echo requests to %s went unanswered.", check.Sent, check.Target),
			"Inspect IPv6 firewall rules, the upstream IPv6 path, and router/prefix advertisements; confirm with an application-level IPv6 check if IPv6 service reachability matters.", 8)}
	}
	if check.PacketLossPct >= 50 {
		return []model.Finding{finding("ipv6-packet-loss", model.SeverityWarning, "network", "IPv6 packets are being dropped",
			fmt.Sprintf("%.0f%% of ICMPv6 echo requests to %s were lost (%d of %d).", check.PacketLossPct, check.Target, check.Sent-check.Received, check.Sent),
			"Inspect the IPv6 network path for congestion or filtering.", 8)}
	}
	return nil
}

// deletedFilesWarningBytes and deletedFilesCriticalBytes are deliberately
// well above what an ordinary rotated log or short-lived temp file leaves
// behind for a moment; this is meant to catch a genuine, sustained "where
// did my disk space go" condition, not routine housekeeping churn.
const (
	deletedFilesWarningBytes  = 200 << 20 // 200 MiB
	deletedFilesCriticalBytes = 2 << 30   // 2 GiB
)

// deletedFilesFindings judges the /proc/*/fd scan. The scan is inherently
// partial for a non-root run (it only sees processes this user can inspect),
// so this only judges what was actually found -- it never claims host-wide
// coverage.
func deletedFilesFindings(df *model.DeletedFiles) []model.Finding {
	if df == nil || !df.Available {
		return nil
	}
	coverageLimited := df.ProcessScanLimited || df.ProcessesSkipped > 0
	if df.TotalBytes < deletedFilesWarningBytes {
		if df.TotalBytes == 0 || !coverageLimited {
			return nil
		}
		eligible := df.ProcessesEligible
		if eligible == 0 {
			eligible = df.ProcessesScanned + df.ProcessesSkipped
		}
		limitations := make([]string, 0, 2)
		if df.ProcessScanLimited {
			limitations = append(limitations, "process scan limit")
		}
		if df.ProcessesSkipped > 0 {
			limitations = append(limitations, fmt.Sprintf("%d process(es) skipped due to permission restrictions", df.ProcessesSkipped))
		}
		coverage := fmt.Sprintf("%d/%d process(es) checked", df.ProcessesScanned, eligible)
		if df.ProcessesSkipped > 0 {
			coverage += fmt.Sprintf("; %d skipped due to permissions", df.ProcessesSkipped)
		}
		if df.ProcessScanLimited {
			coverage += "; scan reached the configured process limit"
		}
		return []model.Finding{{
			ID:       "deleted-files-coverage",
			Severity: model.SeverityInfo,
			Category: "storage",
			Title:    "Deleted-file scan has reduced coverage",
			Summary:  fmt.Sprintf("Found %s across %d unique deleted file(s), below the %s warning threshold. The scan checked %d/%d process(es); reduced coverage: %s.", bytes(df.TotalBytes), df.UniqueFiles, bytes(deletedFilesWarningBytes), df.ProcessesScanned, eligible, strings.Join(limitations, ", ")),
			Evidence: []model.Evidence{{
				Label: "Coverage",
				Value: coverage + ".",
			}},
			Suggestion: "Run glimpse with sudo for complete process visibility if reclaiming deleted-file space is important.",
		}}
	}
	severity, impact := model.SeverityWarning, 10
	if df.TotalBytes >= deletedFilesCriticalBytes {
		severity, impact = model.SeverityCritical, 20
	}
	detail := fmt.Sprintf("%s across %d unique deleted file(s) is still allocated because %d process(es) hold references to them (%d total open reference(s)); this space will not be freed until those descriptors close.",
		bytes(df.TotalBytes), df.UniqueFiles, df.ProcessesHolding, df.TotalReferences)

	var evidence []model.Evidence
	if df.LargestHolderBytes > 0 {
		label := df.LargestHolderCommand
		if label == "" {
			label = fmt.Sprintf("pid %d", df.LargestHolderPID)
		}
		evidence = append(evidence, model.Evidence{Label: "Largest holder", Value: fmt.Sprintf("%s (pid %d), %s retained across %d unique file(s)", label, df.LargestHolderPID, bytes(df.LargestHolderBytes), df.LargestHolderFileCount)})
	}
	if len(df.Files) > 0 {
		top := df.Files[0]
		evidence = append(evidence, model.Evidence{Label: "Largest file", Value: fmt.Sprintf("%s at %s", bytes(top.Bytes), top.Path)})
	}

	return []model.Finding{{
		ID: "deleted-files-open", Severity: severity, Category: "storage",
		Title:       "Deleted files are still held open, consuming disk space",
		Summary:     detail,
		Evidence:    evidence,
		Suggestion:  "Identify the process(es) holding these descriptors (lsof +L1, or inspect /proc/<pid>/fd) and restart or signal them to release the space.",
		ScoreImpact: impact,
	}}
}

func resolvedFailed(failed []string) bool {
	for _, unit := range failed {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(unit)), ".service")
		if name == "systemd-resolved" {
			return true
		}
	}
	return false
}

func hardwareErrorFindings(hardware *model.HardwareErrors) []model.Finding {
	if hardware == nil || !hardware.Available {
		return nil
	}
	var findings []model.Finding
	for _, controller := range hardware.Controllers {
		if controller.UncorrectableErrors > 0 {
			findings = append(findings, finding("hardware-uncorrectable-"+controller.Name, model.SeverityInfo, "hardware", "Historical uncorrectable hardware errors", fmt.Sprintf("EDAC controller %s has recorded %d uncorrectable error(s) since boot; this counter is cumulative.", controller.Name, controller.UncorrectableErrors), "Correlate with recent kernel machine-check events and inspect hardware promptly if the counter is increasing.", 0))
		} else if controller.CorrectableErrors > 0 {
			findings = append(findings, finding("hardware-correctable-"+controller.Name, model.SeverityInfo, "hardware", "Historical correctable hardware errors", fmt.Sprintf("EDAC controller %s has recorded %d correctable error(s) since boot; this counter is cumulative.", controller.Name, controller.CorrectableErrors), "Monitor the counter and inspect memory, firmware, and kernel hardware-error logs if it increases.", 0))
		}
	}
	return findings
}

// failedAuthWarning is the count within the measured journal window that turns
// routine background noise into a reportable authentication problem.
const failedAuthWarning = 30
