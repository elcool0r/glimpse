# Glimpse health checks

This is the reference for the checks enabled by the default profile. It explains
what Glimpse reads, when a finding is emitted, and why a check may be visible
only in `--verbose` or JSON. Thresholds are deliberately conservative: a
single noisy counter should not turn a healthy host red.

## Runtime profile

| Setting | Default |
| --- | --- |
| Sample window | 5 seconds (`--duration` selects a longer, more thorough window, e.g. `--duration 60s`) |
| Sample interval | 1 second |
| Command timeout | 3 seconds unless a collector documents its own bound (kernel and storage 4s, ZFS and per-device SMART 5s) |
| Collection boundaries | Baseline and final collection each get their own 30-second budget; gauge-only collectors run once, at the final boundary |
| Hung commands | Every external command is bounded by a context deadline and a wait deadline, so a process that ignores the kill cannot hang the report |
| Network activity | Local kernel counters, sockets, routes, and logs only, plus several small active probes on by default: DNS resolution against the configured local nameserver and against `1.1.1.1`, ICMP pings to the default gateway and to `1.1.1.1`, an IPv6 ping (only if a global IPv6 address is configured), a path-MTU probe against `1.1.1.1`, and an HTTP/HTTPS GET to `example.com` (forced over IPv4). `--disable-external-checks` turns all of these off and falls back to purely passive collection |
| Containers | Docker and Podman are inspected automatically when a local runtime is available; use `--no-containers` to disable |
| Unknown data | Missing permissions, commands, or kernel interfaces are coverage diagnostics and do not become health failures |

The human report is intentionally compact. Healthy inventories are summarized;
raw values, inventories, collector diagnostics, and process rankings are in
`--verbose` or `--json`. A check can therefore be running and healthy without
adding a long section to the normal report.

Rows use one shared status scheme: green `OK`, cyan `INFO`, yellow `WARN`,
red `CRIT`, and magenta `UNKNOWN`. The same status color is applied to the
section label and badge; `--no-color` keeps the text labels and removes ANSI
styling.

## Host and workload checks

| Check / source | Informational result | Warning default | Critical / error default |
| --- | --- | --- | --- |
| CPU utilization, load, and CPU PSI (`/proc/stat`, `/proc/loadavg`, `/proc/pressure/cpu`) | Values are reported in the CPU summary; top processes are verbose-only | Sampled utilization ≥90%, load-1 above the CPU count, **and** CPU PSI some avg10 ≥5% | No standalone critical threshold |
| CPU steal | Steal time is retained in metrics | Steal ≥10% with CPU PSI some avg10 ≥5% | None |
| Memory available, PSI, swap, swappiness, page faults (`/proc/meminfo`, `/proc/vmstat`, `/proc/sys/vm/swappiness`) | High swappiness (≥80) while available memory is <10% and swap/PSI is active is informational | Available memory <8% with memory PSI some avg10 ≥1% or sampled swap activity; major-fault pressure also warns when page faults ≥100,000, major faults ≥1,000, and available memory <15% | None |
| Filesystem space and inodes (`statfs`, `/proc/self/mountinfo`) | Read-only mounts are reported as informational when they are not an expected image filesystem. Utilization is measured against space available to a normal process, matching `df`, so the root reserve is not counted as free. `tmpfs` is included: it is RAM-backed but genuinely mountable with a fixed size and can fill up exactly like a disk-backed filesystem | Space ≥85% used; inode use ≥90% | Space ≥95% used; inode use ≥98% |
| Filesystem probe coverage | Unsupported or potentially blocking filesystem types are named in verbose diagnostics | None | None; unavailable probes do not fail the host |
| Disk I/O (`/proc/diskstats`) | Per-device rates, utilization, queue depth, and latency; loop devices and virtual mapper layers are omitted | Utilization ≥85% plus queue depth ≥2 or latency ≥50 ms, corroborated by I/O PSI, CPU iowait, or blocked tasks | Utilization ≥95%, queue depth ≥4, and corroborating I/O pressure or iowait |
| Network interface counters (`/proc/net/dev`) | Rates and device names are summarized. The negotiated link speed, duplex, carrier state, and MTU are read from sysfs and reported as gauges, so they remain available even when no sampling interval could be derived | At least 10 errors, drops, or FIFO overruns and ≥1% of packets for that direction and signal | None |
| Physical link errors (`/proc/net/dev`) | Frame errors, carrier losses, and collisions describe the link rather than the load, so they are judged by count rather than by ratio | At least 10 frame errors and carrier losses combined; or at least 10 collisions on a link the driver reports as full duplex, which is the usual symptom of a duplex mismatch. Collisions on a half-duplex segment are normal and never warn | None |
| Thermal sensors (`/sys/class/thermal`, hwmon) | Sensor names are translated to a readable label where possible; within 5°C of the sensor's explicit critical limit is informational, because CPU packages routinely boost close to Tjmax | Temperature at or above the sensor's own critical limit | No generic threshold without a kernel-provided critical limit |
| Process sampling (`/proc`) | Top CPU and resident-RAM (RSS) processes are available with `--verbose`; duplicate PIDs are removed between lists | None from ranking alone | None |
| Zombie processes (`/proc`) | Count and identities are informational; parent details are verbose | None | None |
| Failed systemd units (`systemctl --failed`) | None | None | Any failed unit |
| Kernel event scan (current boot / bounded recent journal) | Records carry their age. An event older than one hour is reported one severity lower, so an overnight incident does not read as urgently at noon as it did at 03:00. Three scans run: the main kernel-ring-buffer scan at warning-and-above priority (oom, panic, oops, hardware error, filesystem corruption/error, nvme/io error, NETDEV WATCHDOG, a filesystem remounted read-only, thermal throttling, zfs error, a blocked task); a second, `--grep`-targeted kernel-ring-buffer scan for two lower-priority patterns that would otherwise be crowded out (a process segfault; a physical NIC's own "Link is Up/Down" message -- software interfaces such as veth, bridges, tap devices, and WireGuard do not emit this message, so no separate detection is needed to exclude them); and a third, non-kernel journal-wide scan for "No space left on device", which is logged by the application that hit it, not the kernel, giving a real timestamp for a filesystem that was full earlier even if it is not full now. A link coming back up is reported as informational with no score impact -- it is the recovery half of a down/up pair, not a fault | Explicit kernel warning patterns, or an older critical pattern | OOM/cgroup OOM, hardware error, filesystem corruption or read-only remount, "No space left on device", kernel panic, or kernel oops recorded within the last hour |
| Time synchronization (`timedatectl` or `chronyc`) | Service and measured offset | Unsynchronized, or absolute offset ≥1,000 ms | Absolute offset ≥5,000 ms |
| Resource limits (`/proc/sys`, `/proc/sys/fs`, conntrack) | Current/max values are available in verbose output. The task count from `/proc/loadavg` counts threads and is compared against the lower of `threads-max` and `pid_max`, not against `pid_max` alone. Inotify limits are reported as capacity facts; the kernel exposes no global watch count, so there is no usage rule for them | File descriptors, tasks, or conntrack ≥90% used | ≥98% used |
| Connection tracking drops (`/proc/net/stat/nf_conntrack`) | Per-CPU drop, early-drop, and failed-insert counters are summed and sampled over the window. Columns are read by header name, so a kernel that adds or removes one does not shift the others. This is independent of table utilization: a burst can drop packets while the steady-state count still looks calm | Any drop, early drop, or failed insert during the sample | None |
| Socket table ceilings (`/proc/sys/net/ipv4/tcp_max_tw_buckets`, `tcp_max_orphans`) | The kernel publishes an explicit ceiling for each table, which is what makes a “large” socket count judgeable at all. Where a ceiling cannot be read, no rule is applied rather than an invented threshold | TIME_WAIT or orphaned sockets ≥90% of their ceiling | None |
| cgroup v2 (`/sys/fs/cgroup`) | Current limits and sampled deltas | Memory allocation OOM events; CPU throttling ≥10% of at least 0.1 s CPU use; PIDs ≥95%; container memory ≥95% with corroborating pressure | OOM-kill events in the current cgroup |

## Storage and hardware integrations

| Check / source | Informational result | Warning default | Critical / error default |
| --- | --- | --- | --- |
| SMART / NVMe (`smartctl`, `nvme`) | Vendor-neutral health facts and wear values; virtual-only `vd*`/`xvd*` disks are skipped. Devices are probed concurrently under a budget that scales with device count, and any device the sweep could not reach is named in coverage diagnostics; a compact `Devices` row shows how many were checked | Spare below 10% or endurance used ≥95% | SMART overall failure, NVMe critical warning, pending/uncorrectable sectors, or media errors |
| ZFS (`zpool status`) | ONLINE pools are a compact `OK`; scrub/resilver in progress is informational | Any read, write, or checksum error on an ONLINE pool | Pool health other than ONLINE, or permanent data errors |
| Software RAID (`/proc/mdstat`) | Active/clean arrays are summarized | Rebuild/resync is informational | Array state other than active/clean |
| LVM (`pvs`, `vgs`, `lvs`) | PV/VG/LV counts are shown in verbose output and a compact storage summary. Sizes are requested in bytes rather than parsed from display strings such as `<3.64t` | Positional attribute bits only: LV state suspended/invalid/mapped-failure/unknown, LV health partial/refresh-needed/mismatched/unknown, VG partial or read-only. Healthy snapshot, origin, thin and pvmove volumes are not flagged | None; a missing or denied command is unavailable coverage, reported as such |
| Persistent mounts (`/etc/fstab` + mountinfo) | Active entries are counted; `nofail` and `noauto` are recognized; swap files are excluded | A non-swap fstab entry is known to be absent and is not marked `nofail`/`noauto` | None |
| EDAC hardware counters (`/sys/devices/system/edac`) | Nonzero correctable or uncorrectable counters are informational cumulative evidence | None from the counter alone; correlate an increasing counter with kernel events | None from the counter alone |

Swap entries such as `/swap.img none swap sw 0 0` are intentionally excluded
from persistent-mount warnings because `none` is a pseudo mount point.

## Containers

Docker and Podman checks use local CLI/API access only. Every discovered
container is eligible for state and last-hour log inspection; bounded command
output and a shared time budget protect the host from a hung runtime. The
limits are implementation safeguards, not a claim that only a small sample was
checked.

| Check | Informational result | Warning default | Critical / error default |
| --- | --- | --- | --- |
| Runtime availability and inventory | Runtime name and running count | None | None; missing runtime is simply unavailable |
| Health status | Healthy containers stay in the compact summary | Unhealthy health check | None |
| Restarts and exit state | Stable containers are omitted from detail | Any restart during the sample; exited container with a restart policy | Three or more restarts during the sample; OOM-killed container |
| Console logs (combined stdout/stderr from `docker logs` or `podman logs`) | Lines matching generic error or failure wording are kept as informational evidence with no score impact: an access-log path, a package name or a successful retry contains those words and is not a fault. Output larger than the retained bound is truncated and reported as truncated, never discarded | Concrete failure signatures only: OOM, panic, segmentation fault, uncaught exception, data corruption, read-only filesystem | None; a runtime or log-read failure is coverage diagnostics, and a container whose logs could not be read is not counted as checked |

## Security and maintenance

| Check / source | Informational result | Warning default | Critical / error default |
| --- | --- | --- | --- |
| Reboot marker (`/var/run/reboot-required`) | Pending reboot marker | None | None |
| Kernel taint (`/proc/sys/kernel/tainted`, `/proc/modules`) | Taint is shown in verbose diagnostics. Taint caused only by ZFS/SPL (including the common mask 4097 case) is hidden in the normal report because it is expected for that installation | Other taint remains informational and does not lower the score | None |
| SELinux / AppArmor state | Enforcing/enabled and unknown states are summarized. Denials are counted from the kernel journal over the same one-hour window | SELinux permissive; SELinux or AppArmor denials in the window | None |
| Kernel vulnerability files (`/sys/devices/system/cpu/vulnerabilities`) | Non-vulnerable and mitigated statuses are quiet | A status beginning with `Vulnerable` | None |
| Failed authentication events (`journalctl SYSLOG_FACILITY=10`, last hour) | Any failed authentication event in the window is informational. The window and facility are both explicit, so the count has a defined population; an unfiltered record tail found these events only by chance | Thirty or more events within the last hour | None |
| Core dumps (`coredumpctl --since=-24h`) | None | Any core dump in the last 24 hours | None |
| Crash artifacts (`/var/crash`) | Any artifact is informational: the directory is never cleared automatically, so its contents are historical evidence rather than a current fault | None | None |
| Active sessions (`who`) | Session count is informational/verbose | None | None |

## Network state inventory

Local `ss` and `ip` commands inventory listening sockets, connection states,
and routes. These facts are shown as a compact checked summary and expanded in
verbose output. A successfully collected routing table with no default route is
informational; Glimpse does not assume that every host should have one.

The resolver configuration in `/etc/resolv.conf` is read as a plain file, so it
is reported whether or not iproute2 is installed. Nameservers, search domains,
and whether every nameserver is a systemd-resolved stub address are recorded.
Two faults are judged from it, and only two, because neither requires sending a
query: a configuration with no nameserver at all (warning), and a stub-only
configuration whose `systemd-resolved` unit has actually failed (critical). A
stub-only configuration on its own is the default on most systemd
distributions and never warns. Whether a configured resolver actually answers
is tested by the active DNS resolution check below.

TCP protocol counters (`/proc/net/snmp`, `/proc/net/netstat`, `/proc/net/sockstat`)
are collected by the default profile. The rules are retransmits ≥2% of at least
100 outbound segments (warning, ≥10% critical), any listen overflow or drop
(warning, and the finding names `net.core.somaxconn` so the backlog ceiling is
actionable), and ≥10% failed connection attempts across at least 50 opens
(warning). IP reassembly and fragmentation failure counters are collected from
the same source as local evidence for a future path-MTU verdict; they carry no
rule of their own yet. The probe is rootless and uses no external commands.

## Active network checks

These checks send real packets instead of only reading local state. All of
them are on by default; `--disable-external-checks` turns them off.

| Check / source | Informational result | Warning default | Critical / error default |
| --- | --- | --- | --- |
| DNS resolution, local nameserver (`internal/collect/dnsresolution`) | Resolved name, server, and latency are shown in verbose output. Skipped entirely when no nameserver is configured | Resolution fails against the local nameserver while the external resolver succeeds for the same query | None from this row alone; see "both failed" below |
| DNS resolution, external (`1.1.1.1`) | Resolved name, server, and latency are shown in verbose output | None | Resolution fails against `1.1.1.1` while the local nameserver succeeds, or both fail, or the external one fails with no local nameserver configured: this host cannot resolve names anywhere on the public internet |
| Gateway ping (`internal/collect/gatewayping`) | Sent/received counts and average latency of a small ICMP echo series to the default gateway, run via the system `ping` binary (bounded, timed out, output parsed regardless of exit code since ping exits nonzero on any loss). A host without a `ping` binary reports the check unavailable rather than failing or warning. Skipped entirely when no default route is configured | Majority packet loss (≥50%), or average latency ≥200ms (a same-segment gateway is normally single-digit milliseconds) | No reply at all, or average latency ≥500ms |
| External ICMP ping (`internal/collect/icmpcheck`) | Sent/received counts and average latency of a ping series to `1.1.1.1`, independent of the default gateway -- a healthy gateway only proves the local link works | Majority packet loss (≥50%), or average latency ≥300ms | No reply at all, or average latency ≥800ms |
| IPv6 ping (`internal/collect/ipv6check`) | Same as the external ICMP check, but over IPv6 to a Cloudflare anchor. Skipped entirely unless `/proc/net/if_inet6` shows a global-scope address; an IPv4-only host is not a fault | Majority packet loss (≥50%) | No reply at all, despite this host having a global IPv6 address configured |
| Path MTU discovery (`internal/collect/pathmtu`) | An ordinary baseline ping to `1.1.1.1`, then a descending series of non-fragmentable pings (`ping -M do -s <size>`, 1472 down to 548 bytes), reporting the largest size that got through. The full 1500-byte ceiling working is quiet; a smaller size getting through is a reduced but working path MTU, normal and healthy with PPPoE, VPNs, or tunnels when path MTU discovery (PMTUD) is working. Skipped entirely when the anchor host is unreachable at all (a connectivity fact the gateway/DNS/ICMP checks already cover) or when the local `ping` does not support `-M do` | None | No size at all got through despite the baseline succeeding: PMTUD itself is not working (commonly because the ICMP "fragmentation needed" replies it depends on are filtered), which stalls large transfers while small traffic and pings work fine |
| HTTP/HTTPS GET (`internal/collect/httpcheck`) | A GET to `http://example.com/` and to `https://example.com/` succeeding (any status code, since this tests reachability, not content) is quiet; latency and status code are shown in verbose output. Connections are forced over IPv4, so a firewall rule scoped to IPv4 (the common way to test this with plain `iptables`) cannot be silently bypassed by an IPv6 path. Every failure combination (HTTP only, HTTPS only, or both) is reported here, at informational severity, because an intentionally restricted host (firewall, proxy, air-gapped network) produces the identical signal to a genuine fault | None; never escalated past informational | None |

## Local file-descriptor checks

| Check / source | Informational result | Warning default | Critical / error default |
| --- | --- | --- | --- |
| Deleted-but-open files (`internal/collect/deletedfiles`) | A bounded scan of `/proc/*/fd` for descriptors still open on unlinked files -- the "disk is full but nothing looks large" symptom. Space is counted once per unique `(device, inode)`, never per fd, PID, path, or size: the same deleted file held open on several file descriptors (a common journald/podman pattern) contributes its size once, while distinct files that happen to share a size or a display name are still counted separately. Reports allocated space (`st_blocks * 512`) rather than logical size when available, so a sparse file is not overstated. Only sees processes this user can inspect; processes scanned vs. skipped is shown explicitly rather than under-reporting silently. Individual files under 1 MiB are counted toward the total but not listed. Anything living on tmpfs/shmem (`statfs` type check) is excluded entirely, not just by name: `memfd_create()` objects -- for example the .NET runtime's JIT "doublemapper" -- appear identically to a deleted regular file, "(deleted)" suffix included, but are RAM-backed with a virtual/logical size, not real disk usage | Total held-open bytes ≥200 MiB, naming the largest holder (the process retaining the most *unique* space, not the most references) and the single largest file | Total held-open bytes ≥2 GiB |

## Recent events timeline

Shown automatically alongside a critical finding, or always with `--events`.
It answers "what happened today, and roughly when" -- a chronological,
source-tagged list, not a second copy of the health verdict.

Only two kinds of fact appear here:

- **A real historical timestamp.** Kernel/journal events, package-manager
  transactions, and SSH logins all carry (or can derive) the actual moment
  they happened, independent of when glimpse itself happened to run.
- **A live fact with no historical record of when it started.** A
  currently-failed systemd unit, or a container this sample found
  unhealthy/OOM-killed/restarted, is stamped "now" -- true for the instant
  this report ran, not a claim about exactly when the fault began.

Deliberately excluded: ongoing state (a filesystem at 95%, a degraded RAID
array) has no discrete moment this report can point to, so inventing a
timestamp would be worse than leaving it in the normal metric row and
Details instead. Only today (local midnight through now) is shown.

| Source | What it covers | Notes |
| --- | --- | --- |
| `kernel` | Every kernel event scan pattern (see above) | Real timestamp from the journal record's own age |
| a container runtime name (e.g. `docker`, `podman`) | OOM-killed, unhealthy, restarted, or exited-despite-restart-policy containers; container log lines matching the same concrete failure signatures the analyzer treats as actionable | State facts are stamped "now"; log-line facts carry a real timestamp |
| `systemd` | Failed units (stamped "now"); unit (re)starts, from systemd's own `ActiveEnterTimestamp` (a real timestamp, independent of glimpse's own sampling window -- a restart from ten minutes before glimpse ran still appears, which a live restart-counter delta cannot see) | The live restart count observed during this specific sample is folded into the precisely-timed line when both are known |
| `apt` | One entry per apt transaction from `/var/log/apt/history.log`, summarized ("3 packages upgraded"), never one entry per package | Debian/Ubuntu only |
| `yum` | One entry per distinct-minute group of lines in the classic `/var/log/yum.log` | RHEL/CentOS 7 and earlier; a modern dnf-only host with no `yum.log` is not covered -- dnf's own history lives in a SQLite database this project does not take a dependency on to read |
| `ssh` | Successful interactive logins (user, source address, and method) from the authpriv journal | A session that immediately requests the sftp subsystem is excluded on a best-effort basis (covers `sftp` and, since OpenSSH 9.0, `scp`'s default SFTP-protocol mode); a non-interactive `ssh host command` invocation cannot be distinguished from a real login at this log level and may still appear |

## Severity and coverage

`OK` means no finding was raised for the check. `INFO` records useful context
without score impact. `WARN` and `CRIT` identify evidence that merits action and
reduce the score according to the finding. No single category may subtract more
than 30 points, so one noisy subsystem cannot floor the score and erase the
difference between a host with one problem and a host with nothing working.

A missing optional source is shown as `unavailable` in collection diagnostics,
with the check name; it is not silently counted as healthy. A collection
boundary that exceeded its budget is also partial coverage, not a failed report.
The report status is `INSUFFICIENT DATA` only when the run was interrupted or
when no core observation (CPU, memory, filesystems) is available.
