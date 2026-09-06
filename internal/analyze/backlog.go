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
	findings = append(findings, hardwareErrorFindings(report.Metrics.Hardware)...)
	return findings
}

func memoryBacklogFindings(memory *model.Memory, pressure *model.Pressure) []model.Finding {
	if memory == nil {
		return nil
	}
	var findings []model.Finding
	if memory.Swappiness != nil && *memory.Swappiness >= 80 && memory.AvailableFraction < .10 && (memory.SwapInBytes > 0 || pressure != nil && pressure.Memory.SomeAvg10 >= 1) {
		findings = append(findings, finding("memory-swappiness", model.SeverityInfo, "memory", "High swappiness during memory pressure", fmt.Sprintf("vm.swappiness is %d while MemAvailable is %.1f%% and swap or memory pressure was observed.", *memory.Swappiness, memory.AvailableFraction*100), "Review swappiness alongside workload latency and memory policy before changing it.", 0))
	}
	if memory.PageFaults >= 100000 && memory.MajorFaults >= 1000 && memory.AvailableFraction < .15 {
		findings = append(findings, finding("memory-fault-pressure", model.SeverityWarning, "memory", "Memory fault pressure observed", fmt.Sprintf("The sample recorded %d page faults and %d major faults while only %.1f%% of memory was available.", memory.PageFaults, memory.MajorFaults, memory.AvailableFraction*100), "Inspect memory pressure, swap activity, and the largest memory consumers.", 8))
	}
	return findings
}

func storageBacklogFindings(raids []model.SoftwareRAID, lvm *model.LVM, mounts []model.MountCheck) []model.Finding {
	var findings []model.Finding
	for _, raid := range raids {
		state := strings.ToLower(strings.TrimSpace(raid.State))
		if state != "active" && state != "clean" {
			findings = append(findings, finding("raid-"+raid.Device, model.SeverityCritical, "storage", "Software RAID is degraded", fmt.Sprintf("%s reports state %s.", raid.Device, raid.State), "Inspect /proc/mdstat and repair or replace the affected member devices.", 25))
		} else if raid.ResyncProgress != "" {
			findings = append(findings, finding("raid-resync-"+raid.Device, model.SeverityInfo, "storage", "Software RAID is rebuilding", fmt.Sprintf("%s has an active recovery or resync operation.", raid.Device), "Allow the rebuild to finish and verify the array returns to a clean state.", 0))
		}
	}
	if lvm != nil {
		// The collector interprets the positional attribute bits; analysis and
		// rendering both read its verdict, so there is one reading of them.
		for _, vg := range lvm.VolumeGroups {
			if vg.NeedsReview {
				findings = append(findings, finding("lvm-vg-"+vg.Name, model.SeverityWarning, "storage", "LVM volume group needs review", fmt.Sprintf("Volume group %s is %s (attributes %q).", vg.Name, vg.ReviewReason, vg.Attr), "Inspect the volume group with vgs and verify it is writable and complete.", 12))
			}
		}
		for _, lv := range lvm.LogicalVolumes {
			if lv.NeedsReview {
				findings = append(findings, finding("lvm-lv-"+lv.Group+"-"+lv.Name, model.SeverityWarning, "storage", "LVM logical volume needs review", fmt.Sprintf("Logical volume %s/%s is %s (attributes %q).", lv.Group, lv.Name, lv.ReviewReason, lv.Attr), "Inspect the logical volume with lvs and verify it is active and complete.", 12))
			}
		}
	}
	for _, mount := range mounts {
		if !mount.ActiveKnown || mount.Active || mountHasOption(mount, "nofail") || mountHasOption(mount, "noauto") {
			continue
		}
		findings = append(findings, finding("mount-missing-"+mount.MountPoint, model.SeverityWarning, "storage", "Persistent mount is unavailable", fmt.Sprintf("%s is listed in /etc/fstab but is not currently mounted.", mount.MountPoint), "Verify the device, filesystem, and intended mount policy before mounting it.", 10))
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
		findings = append(findings, finding("security-failed-auth", severity, "security", "Failed authentication attempts", fmt.Sprintf("The authentication journal for %s contains %d failed authentication event(s).", window, *s.FailedAuthAttempts), "Review source addresses, exposed services, and authentication policy in the system journal.", impact))
	}
	if s.SELinuxDenials != nil && *s.SELinuxDenials > 0 {
		findings = append(findings, finding("security-selinux-denials", model.SeverityWarning, "security", "SELinux denials observed", fmt.Sprintf("The kernel journal for %s contains %d SELinux denial event(s).", window, *s.SELinuxDenials), "Review the denied operation and policy before changing enforcement mode.", 8))
	}
	if s.AppArmorDenials != nil && *s.AppArmorDenials > 0 {
		findings = append(findings, finding("security-apparmor-denials", model.SeverityWarning, "security", "AppArmor denials observed", fmt.Sprintf("The kernel journal for %s contains %d AppArmor denial event(s).", window, *s.AppArmorDenials), "Review the affected profile and denied operation before changing policy.", 8))
	}
	if s.CoreDumps != nil && *s.CoreDumps > 0 {
		findings = append(findings, finding("security-core-dumps", model.SeverityWarning, "security", "Recent core dumps found", fmt.Sprintf("The recent crash window contains %d core dump(s).", *s.CoreDumps), "Inspect coredumpctl and the affected service stack for the root cause.", 10))
	}
	if len(s.CrashArtifacts) > 0 {
		// /var/crash is an unbounded directory that nothing clears on its own.
		// Its contents are historical evidence, like the cumulative EDAC
		// counters, and are reported the same way: informational, no score
		// impact. A crash inside the measured window is reported by
		// coredumpctl above.
		findings = append(findings, finding("security-crash-artifacts", model.SeverityInfo, "security", "Crash artifacts present", fmt.Sprintf("The crash directory contains %d artifact(s); this directory is not cleared automatically, so entries may be old.", len(s.CrashArtifacts)), "Review the artifacts and clear them only after preserving evidence needed for diagnosis.", 0))
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
		return []model.Finding{finding("dns-no-nameserver", model.SeverityWarning, "network", "No DNS nameserver configured",
			"The resolver configuration lists no nameserver, so name resolution can only use static entries.",
			"Confirm that this host resolves names through /etc/hosts by design, or restore the expected nameserver configuration.", 12)}
	}
	// Pointing only at the stub delegates all resolution to systemd-resolved.
	// That is a normal arrangement on its own, so it is reported only when the
	// service it depends on has actually failed -- then DNS is provably broken
	// rather than merely dependent.
	if dns.StubResolver && systemd != nil && systemd.Available && resolvedFailed(systemd.FailedUnits) {
		return []model.Finding{finding("dns-stub-resolver-failed", model.SeverityCritical, "network", "DNS stub resolver is configured but its service failed",
			"Every configured nameserver is the local systemd-resolved stub, and systemd-resolved is in a failed state.",
			"Inspect systemd-resolved and restart it; until it runs, this host cannot resolve names.", 20)}
	}
	return nil
}

// dnsResolutionFindings judges the active probe: --check-dns-resolution sends
// a real query to the local nameserver and to 1.1.1.1. Losing only the
// external one is common on hosts with restricted outbound access and is not
// by itself a fault, so it stays informational; losing the local resolver, or
// losing both, means names cannot be resolved and is reported accordingly.
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
		return []model.Finding{finding("dns-resolution-failed", model.SeverityCritical, "network", "DNS resolution is not working",
			detail, "Inspect the resolver configuration, local DNS service, and network path to any DNS server.", 25)}
	case localAttempted && !localOK:
		return []model.Finding{finding("dns-resolution-local-failed", model.SeverityWarning, "network", "Local DNS server is not resolving names",
			fmt.Sprintf("Resolving %s against the configured nameserver (%s) failed, but the same query succeeded against %s.", resolution.Local.Domain, resolution.Local.Server, resolution.External.Server),
			"Inspect the local DNS server or forwarder; clients depending on it cannot resolve names.", 15)}
	case externalAttempted && !externalOK:
		return []model.Finding{finding("dns-resolution-external-failed", model.SeverityInfo, "network", "External DNS server unreachable",
			fmt.Sprintf("Resolving %s against %s failed, though the local nameserver resolves it; this may be intentional (restricted outbound access).", resolution.External.Domain, resolution.External.Server),
			"Confirm whether outbound DNS to public resolvers is intentionally restricted.", 0)}
	}
	return nil
}

// gatewayFindings judges the active gateway probe. No reply at all means
// nothing off-link is reachable; partial loss is reported only past a
// majority threshold so an occasional dropped ping on a healthy link does not
// warn.
func gatewayFindings(check *model.GatewayCheck) []model.Finding {
	if check == nil || !check.Available || check.Sent == 0 {
		return nil
	}
	if check.Received == 0 {
		return []model.Finding{finding("gateway-unreachable", model.SeverityCritical, "network", "Default gateway is not responding",
			fmt.Sprintf("All %d ICMP echo requests to the default gateway (%s) went unanswered.", check.Sent, check.Gateway),
			"Inspect the local network link, switch/router, and default gateway configuration.", 20)}
	}
	if check.PacketLossPct >= 50 {
		return []model.Finding{finding("gateway-packet-loss", model.SeverityWarning, "network", "Default gateway is dropping pings",
			fmt.Sprintf("%.0f%% of ICMP echo requests to the default gateway (%s) were lost (%d of %d).", check.PacketLossPct, check.Gateway, check.Sent-check.Received, check.Sent),
			"Inspect the local network link and gateway health.", 10)}
	}
	return nil
}

// pathMTUFindings judges the discovered path MTU, not just whether the
// single largest size got through. A dropped baseline ping means the anchor
// host is unreachable right now, which the gateway and DNS checks already
// speak to -- it says nothing about MTU specifically, so it produces no
// finding here. A reduced but discovered path MTU is normal and healthy with
// PPPoE, VPNs, and tunnels when path MTU discovery is working, so it is
// informational, not a warning; only the absence of any usable size at all
// -- evidence that PMTUD itself is not working, typically because the ICMP
// "fragmentation needed" replies that drive it are being filtered -- is the
// actual black-hole finding.
func pathMTUFindings(check *model.PathMTUCheck) []model.Finding {
	if check == nil || !check.Available || !check.BaselineOK {
		return nil
	}
	if check.DiscoveredMTU == 0 {
		return []model.Finding{finding("path-mtu-blackhole", model.SeverityWarning, "network", "Possible path MTU black hole",
			fmt.Sprintf("Small packets to %s succeed, but every non-fragmentable packet size down to %d bytes failed; no usable path MTU could be discovered.", check.Target, check.FloorMTU),
			"Inspect whether ICMP \"fragmentation needed\" messages are being filtered on the path (path MTU discovery depends on them), and any VPN/tunnel/middlebox MTU settings; large transfers over this path may hang or stall even though small ones and pings work.", 12)}
	}
	if check.DiscoveredMTU < check.CeilingMTU {
		return []model.Finding{finding("path-mtu-reduced", model.SeverityInfo, "network", fmt.Sprintf("Path MTU is %d bytes, not %d -- this is normal, not a fault", check.DiscoveredMTU, check.CeilingMTU),
			fmt.Sprintf("Path MTU to %s was cleanly discovered at %d of %d tested bytes. A reduced path MTU is expected and healthy behind a VPN, tunnel, or PPPoE connection as long as path MTU discovery (the mechanism that found this size) is working, which it is here.", check.Target, check.DiscoveredMTU, check.CeilingMTU),
			"No action needed if large transfers over this path already work normally.", 0)}
	}
	return nil
}

// httpCheckFindings judges the outbound web probe conservatively: an
// intentionally firewalled, proxied, or air-gapped host produces exactly the
// same signal as a genuine fault, and the former is common and legitimate.
// Every finding here is therefore informational only, the same treatment the
// external-only DNS resolution failure gets.
func httpCheckFindings(check *model.HTTPCheck) []model.Finding {
	if check == nil || !check.Available {
		return nil
	}
	httpFailed := check.HTTP != nil && !check.HTTP.Succeeded
	httpsFailed := check.HTTPS != nil && !check.HTTPS.Succeeded
	switch {
	case httpFailed && httpsFailed:
		return []model.Finding{finding("http-check-failed", model.SeverityInfo, "network", "Outbound HTTP and HTTPS requests are both failing",
			fmt.Sprintf("A GET to %s failed (%s) and a GET to %s failed (%s).", check.HTTP.URL, check.HTTP.Error, check.HTTPS.URL, check.HTTPS.Error),
			"Confirm whether outbound web access is intentionally restricted (firewall, proxy, air-gapped network).", 0)}
	case httpsFailed:
		return []model.Finding{finding("https-check-failed", model.SeverityInfo, "network", "Outbound HTTPS request failed while HTTP succeeded",
			fmt.Sprintf("A GET to %s failed: %s", check.HTTPS.URL, check.HTTPS.Error),
			"Inspect TLS interception, certificate trust, or firewalling of port 443 specifically.", 0)}
	case httpFailed:
		return []model.Finding{finding("http-check-http-failed", model.SeverityInfo, "network", "Outbound HTTP request failed while HTTPS succeeded",
			fmt.Sprintf("A GET to %s failed: %s", check.HTTP.URL, check.HTTP.Error),
			"This is unusual since HTTPS succeeded; inspect port 80 filtering specifically.", 0)}
	}
	return nil
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
