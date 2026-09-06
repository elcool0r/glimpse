// Package model defines the normalized, stable data contract shared by
// collectors, analyzers, renderers, and JSON consumers.
package model

import "time"

const SchemaVersion = 1

type Severity string

const (
	SeverityOK       Severity = "ok"
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
	SeverityUnknown  Severity = "unknown"
)

type Report struct {
	SchemaVersion         int                `json:"schema_version"`
	GeneratedAt           time.Time          `json:"generated_at"`
	SampleDurationSeconds float64            `json:"sample_duration_seconds"`
	Host                  Host               `json:"host"`
	Metrics               Metrics            `json:"metrics"`
	Findings              []Finding          `json:"findings"`
	Score                 Score              `json:"score"`
	Collection            []CollectionStatus `json:"collection"`
}

type Host struct {
	Hostname      string     `json:"hostname"`
	OS            string     `json:"os"`
	OSVersion     string     `json:"os_version,omitempty"`
	Kernel        string     `json:"kernel,omitempty"`
	Architecture  string     `json:"architecture"`
	UptimeSeconds float64    `json:"uptime_seconds,omitempty"`
	BootTime      *time.Time `json:"boot_time,omitempty"`
	CPUCount      int        `json:"cpu_count"`
	IsRoot        bool       `json:"is_root"`
}

// Metrics uses normalized base units: bytes, seconds, Celsius, and fractions
// (0..1). Linux PSI averages are the exception: the kernel exposes them as
// percentages (0..100), retained here so values can be compared directly with
// /proc/pressure. Counters are deltas for the sampling window unless
// documented as a current gauge.
type Metrics struct {
	CPU           *CPU               `json:"cpu,omitempty"`
	Memory        *Memory            `json:"memory,omitempty"`
	Pressure      *Pressure          `json:"pressure,omitempty"`
	Filesystems   []Filesystem       `json:"filesystems,omitempty"`
	Network       []Network          `json:"network,omitempty"`
	Thermal       []Thermal          `json:"thermal,omitempty"`
	Processes     *Processes         `json:"processes,omitempty"`
	Systemd       *Systemd           `json:"systemd,omitempty"`
	Kernel        *Kernel            `json:"kernel,omitempty"`
	Disks         []Disk             `json:"disks,omitempty"`
	TCP           *TCP               `json:"tcp,omitempty"`
	Conntrack     *Conntrack         `json:"conntrack,omitempty"`
	DeviceHealth  []DeviceHealth     `json:"device_health,omitempty"`
	TimeSync      *TimeSync          `json:"time_sync,omitempty"`
	Resources     *Resources         `json:"resources,omitempty"`
	Privileges    *Privileges        `json:"privileges,omitempty"`
	CgroupV2      *CgroupV2          `json:"cgroup_v2,omitempty"`
	Containers    []ContainerRuntime `json:"containers,omitempty"`
	ZFSPools      []ZFSPool          `json:"zfs_pools,omitempty"`
	SoftwareRAID  []SoftwareRAID     `json:"software_raid,omitempty"`
	LVM           *LVM               `json:"lvm,omitempty"`
	MountChecks   []MountCheck       `json:"mount_checks,omitempty"`
	Security      *Security          `json:"security,omitempty"`
	NetworkState  *NetworkState      `json:"network_state,omitempty"`
	DNSResolution *DNSResolution     `json:"dns_resolution,omitempty"`
	GatewayCheck  *GatewayCheck      `json:"gateway_check,omitempty"`
	PathMTUCheck  *PathMTUCheck      `json:"path_mtu_check,omitempty"`
	HTTPCheck     *HTTPCheck         `json:"http_check,omitempty"`
	ICMPCheck     *ICMPCheck         `json:"icmp_check,omitempty"`
	IPv6Check     *IPv6Check         `json:"ipv6_check,omitempty"`
	DeletedFiles  *DeletedFiles      `json:"deleted_files,omitempty"`
	Hardware      *HardwareErrors    `json:"hardware_errors,omitempty"`
	Trends        []Trend            `json:"trends,omitempty"`
}

type CPU struct {
	// Sampled is false when gauges are valid but counter deltas are unavailable.
	Sampled     *bool   `json:"sampled,omitempty"`
	Utilization float64 `json:"utilization"`
	User        float64 `json:"user"`
	System      float64 `json:"system"`
	IOWait      float64 `json:"iowait"`
	Steal       float64 `json:"steal"`
	Load1       float64 `json:"load1"`
	Load5       float64 `json:"load5"`
	Load15      float64 `json:"load15"`
	Runnable    int     `json:"runnable,omitempty"`
	Blocked     int     `json:"blocked,omitempty"`
}

type Memory struct {
	// Sampled is false when gauges are valid but counter deltas are unavailable.
	Sampled           *bool   `json:"sampled,omitempty"`
	TotalBytes        uint64  `json:"total_bytes"`
	AvailableBytes    uint64  `json:"available_bytes"`
	SwapTotalBytes    uint64  `json:"swap_total_bytes"`
	SwapFreeBytes     uint64  `json:"swap_free_bytes"`
	SwapInBytes       uint64  `json:"swap_in_bytes_delta,omitempty"`
	SwapOutBytes      uint64  `json:"swap_out_bytes_delta,omitempty"`
	MajorFaults       uint64  `json:"major_faults_delta,omitempty"`
	PageFaults        uint64  `json:"page_faults_delta,omitempty"`
	Swappiness        *uint64 `json:"swappiness,omitempty"`
	AvailableFraction float64 `json:"available_fraction"`
}

type Pressure struct {
	CPU    PressureResource `json:"cpu"`
	Memory PressureResource `json:"memory"`
	IO     PressureResource `json:"io"`
}

type PressureResource struct {
	SomeAvg10 float64 `json:"some_avg10"` // percent (0..100)
	FullAvg10 float64 `json:"full_avg10"` // percent (0..100)
}

type Filesystem struct {
	MountPoint     string  `json:"mount_point"`
	Filesystem     string  `json:"filesystem"`
	Type           string  `json:"type"`
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedFraction   float64 `json:"used_fraction"`
	InodesTotal    uint64  `json:"inodes_total,omitempty"`
	InodesFree     uint64  `json:"inodes_free,omitempty"`
	ReadOnly       bool    `json:"read_only"`
}

type Network struct {
	SampleDurationSeconds float64 `json:"sample_duration_seconds,omitempty"`
	Name                  string  `json:"name"`
	Operational           string  `json:"operational_state,omitempty"`
	RXBytes               uint64  `json:"rx_bytes_delta"`
	TXBytes               uint64  `json:"tx_bytes_delta"`
	RXPackets             uint64  `json:"rx_packets_delta"`
	TXPackets             uint64  `json:"tx_packets_delta"`
	RXErrors              uint64  `json:"rx_errors_delta"`
	TXErrors              uint64  `json:"tx_errors_delta"`
	RXDropped             uint64  `json:"rx_dropped_delta"`
	TXDropped             uint64  `json:"tx_dropped_delta"`
	// Overruns, frame errors, collisions and carrier losses separate a link
	// fault from ordinary load. A drop usually means a full queue; these point
	// at the cable, the transceiver, or a duplex mismatch.
	RXFIFOErrors    uint64 `json:"rx_fifo_errors_delta"`
	TXFIFOErrors    uint64 `json:"tx_fifo_errors_delta"`
	RXFrameErrors   uint64 `json:"rx_frame_errors_delta"`
	TXCarrierErrors uint64 `json:"tx_carrier_errors_delta"`
	Collisions      uint64 `json:"collisions_delta"`
	// Link facts are gauges read from sysfs with the final observation, so they
	// are present whether or not a sampling interval was available.
	MTU       uint64  `json:"mtu,omitempty"`
	Carrier   *bool   `json:"carrier,omitempty"`
	SpeedMbps *uint64 `json:"speed_mbps,omitempty"`
	Duplex    string  `json:"duplex,omitempty"`
}

// NetworkState is a bounded local inventory from ss and ip route. It does not
// contact the network or judge which listening services are intended.
type NetworkState struct {
	Available        bool              `json:"available"`
	RoutesAvailable  bool              `json:"routes_available"`
	ListeningSockets []ListeningSocket `json:"listening_sockets,omitempty"`
	ConnectionStates []ConnectionState `json:"connection_states,omitempty"`
	Routes           []Route           `json:"routes,omitempty"`
	DNS              *DNSConfig        `json:"dns,omitempty"`
}

// DNSConfig is the resolver configuration as written, not a test of whether it
// answers. Confirming that would require sending a query, which the default run
// does not do.
type DNSConfig struct {
	Available     bool     `json:"available"`
	Nameservers   []string `json:"nameservers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
	// StubResolver reports that every nameserver is a systemd-resolved stub
	// address, which makes name resolution depend entirely on that service.
	StubResolver bool `json:"stub_resolver,omitempty"`
}

// DNSResolution is the result of actually sending resolution queries, unlike
// DNSConfig which only reads the configuration file. It exists only when the
// user opted in (--check-dns-resolution): resolving a name against an
// external server contacts the internet, which this tool does not do by
// default.
type DNSResolution struct {
	Available bool                 `json:"available"`
	Local     *DNSResolutionResult `json:"local,omitempty"`
	External  *DNSResolutionResult `json:"external,omitempty"`
}

// DNSResolutionResult is one resolution attempt against one server.
type DNSResolutionResult struct {
	Server        string  `json:"server"`
	Domain        string  `json:"domain"`
	Resolved      bool    `json:"resolved"`
	Error         string  `json:"error,omitempty"`
	LatencyMillis float64 `json:"latency_millis,omitempty"`
}

// GatewayCheck is an active ICMP probe of the default gateway. Like
// DNSResolution, it sends real packets and therefore only runs as part of
// the active-check profile (--disable-external-checks turns it off).
type GatewayCheck struct {
	Available        bool    `json:"available"`
	Gateway          string  `json:"gateway"`
	Sent             int     `json:"sent"`
	Received         int     `json:"received"`
	PacketLossPct    float64 `json:"packet_loss_percent"`
	AvgLatencyMillis float64 `json:"avg_latency_millis,omitempty"`
}

// ICMPCheck actively pings a fixed external anchor host over IPv4 ICMP,
// independently of the default gateway: a healthy gateway only proves the
// local link works, not that anything beyond it is reachable. Like the
// other active checks, it sends real packets and only runs in the
// active-check profile (--disable-external-checks turns it off).
type ICMPCheck struct {
	Available        bool    `json:"available"`
	Target           string  `json:"target"`
	Sent             int     `json:"sent"`
	Received         int     `json:"received"`
	PacketLossPct    float64 `json:"packet_loss_percent"`
	AvgLatencyMillis float64 `json:"avg_latency_millis,omitempty"`
}

// IPv6Check actively pings a fixed external anchor host over IPv6, but only
// when the host has a global IPv6 address configured. An IPv4-only host is
// not a fault and is skipped entirely; this only fires when the host
// believes it has working IPv6 and that belief turns out to be wrong
// (egress filtering, a broken upstream IPv6 path), a failure mode the IPv4
// checks cannot see at all.
type IPv6Check struct {
	Available        bool    `json:"available"`
	Target           string  `json:"target"`
	Sent             int     `json:"sent"`
	Received         int     `json:"received"`
	PacketLossPct    float64 `json:"packet_loss_percent"`
	AvgLatencyMillis float64 `json:"avg_latency_millis,omitempty"`
}

// DeletedFileHolder is one process holding one or more open references
// (file descriptors) to the same deleted inode. FDs is the fd numbers as
// seen under /proc/<pid>/fd, kept for troubleshooting; it does not affect
// how much space the inode counts for, which is independent of how many
// references exist.
type DeletedFileHolder struct {
	PID     int      `json:"pid"`
	Command string   `json:"command,omitempty"`
	FDs     []string `json:"fds,omitempty"`
}

// DeletedFile is one unique deleted (unlinked) inode still occupying disk
// space, identified by (Device, Inode) -- never by path, PID, fd number, or
// size, any of which can coincide across genuinely distinct files or
// genuinely duplicate references to the same one. Bytes is the allocated
// space (st_blocks * 512) when available, falling back to the logical size
// for a filesystem or platform that does not expose block counts; either
// way it is counted exactly once here regardless of how many Holders (or
// how many FDs within one holder) reference this inode.
type DeletedFile struct {
	Device  string              `json:"device"`
	Inode   uint64              `json:"inode"`
	Path    string              `json:"path"`
	Bytes   uint64              `json:"bytes"`
	Holders []DeletedFileHolder `json:"holders,omitempty"`
}

// DeletedFiles is a bounded, best-effort scan of /proc/*/fd for descriptors
// still open on deleted files -- the "df says the disk is full but nothing
// looks large" symptom. It only sees processes this user has permission to
// inspect, which ProcessesScanned/ProcessesSkipped make explicit rather than
// silently under-reporting. TotalBytes sums each unique (device, inode) in
// Files exactly once; TotalReferences counts every fd that pointed at one of
// them, which is normally larger than UniqueFiles when the same deleted
// file is held open more than once (a common pattern for journald and
// similar append-heavy writers).
// LargestHolder* is computed across every unique file this scan found,
// before Files is truncated to the largest few for the report -- summing,
// per process, the bytes of each unique inode it holds exactly once
// (holding the same file on three fds does not triple its contribution to
// that process's total). Ties are broken by the lower PID, so the value is
// stable across runs of an otherwise-identical scan.
type DeletedFiles struct {
	Available              bool          `json:"available"`
	TotalBytes             uint64        `json:"total_bytes"`
	Files                  []DeletedFile `json:"files,omitempty"`
	UniqueFiles            int           `json:"unique_files"`
	ProcessesHolding       int           `json:"processes_holding"`
	TotalReferences        int           `json:"total_references"`
	ProcessesScanned       int           `json:"processes_scanned"`
	ProcessesSkipped       int           `json:"processes_skipped"`
	LargestHolderPID       int           `json:"largest_holder_pid,omitempty"`
	LargestHolderCommand   string        `json:"largest_holder_command,omitempty"`
	LargestHolderBytes     uint64        `json:"largest_holder_bytes,omitempty"`
	LargestHolderFileCount int           `json:"largest_holder_file_count,omitempty"`
}

// PathMTUCheck discovers the usable path MTU to a fixed external anchor by
// sending a baseline ping, then a descending series of non-fragmentable
// pings, and recording the largest one that got through. DiscoveredMTU is 0
// when none of them did -- the actual black-hole case -- and is otherwise
// the discovered value, which may legitimately be below CeilingMTU (normal
// with PPPoE, VPNs, and tunnels when path MTU discovery is working). Like
// DNSResolution and GatewayCheck, it sends real packets and only runs in the
// active-check profile (--disable-external-checks turns it off).
type PathMTUCheck struct {
	Available bool   `json:"available"`
	Target    string `json:"target"`
	// CeilingMTU is the largest size tested (the standard Ethernet MTU);
	// FloorMTU is the smallest size tested before giving up on finding any
	// usable size at all.
	CeilingMTU    int  `json:"ceiling_mtu"`
	FloorMTU      int  `json:"floor_mtu"`
	BaselineOK    bool `json:"baseline_ok"`
	DiscoveredMTU int  `json:"discovered_mtu,omitempty"`
}

// HTTPCheck actively fetches a fixed external URL over HTTP and over HTTPS.
// Like the other active checks, it sends real requests and only runs in the
// active-check profile (--disable-external-checks turns it off).
type HTTPCheck struct {
	Available bool             `json:"available"`
	HTTP      *HTTPCheckResult `json:"http,omitempty"`
	HTTPS     *HTTPCheckResult `json:"https,omitempty"`
}

// HTTPCheckResult is one GET attempt. Succeeded means a complete response
// was received, whatever its status code -- this tests reachability, not
// whether the target's own content is correct.
type HTTPCheckResult struct {
	URL           string  `json:"url"`
	StatusCode    int     `json:"status_code,omitempty"`
	Succeeded     bool    `json:"succeeded"`
	Error         string  `json:"error,omitempty"`
	LatencyMillis float64 `json:"latency_millis,omitempty"`
}

type ListeningSocket struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
}

type ConnectionState struct {
	State string `json:"state"`
	Count uint64 `json:"count"`
}

type Route struct {
	Destination string  `json:"destination"`
	Gateway     string  `json:"gateway,omitempty"`
	Device      string  `json:"device,omitempty"`
	Metric      *uint64 `json:"metric,omitempty"`
}

type Thermal struct {
	Name         string  `json:"name"`
	TemperatureC float64 `json:"temperature_celsius"`
	CriticalC    float64 `json:"critical_celsius,omitempty"`
	MaximumC     float64 `json:"maximum_celsius,omitempty"`
}

type Processes struct {
	Total   int `json:"total"`
	Running int `json:"running"`
	Blocked int `json:"blocked"`
	Zombies int `json:"zombies"`
	// StuckProcesses lists processes observed in uninterruptible sleep (D
	// state) at both the baseline and final sampling boundary -- a single
	// point-in-time D state is common and usually transient (a brief disk or
	// NFS wait), so only a process the kernel still had blocked across the
	// entire sample window is reported here.
	StuckProcesses  []Process `json:"stuck_processes,omitempty"`
	ZombieProcesses []Process `json:"zombie_processes,omitempty"`
	TopCPU          []Process `json:"top_cpu,omitempty"`
	TopRSS          []Process `json:"top_rss,omitempty"`
	CPUSampled      *bool     `json:"cpu_sampled,omitempty"`
}

type Process struct {
	PID           int     `json:"pid"`
	ParentPID     int     `json:"parent_pid,omitempty"`
	Command       string  `json:"command"`
	ParentCommand string  `json:"parent_command,omitempty"`
	CPUFraction   float64 `json:"cpu_fraction,omitempty"`
	CPUSampled    *bool   `json:"cpu_sampled,omitempty"`
	RSSBytes      uint64  `json:"rss_bytes,omitempty"`
	State         string  `json:"state,omitempty"`
}

type Systemd struct {
	Available   bool     `json:"available"`
	FailedUnits []string `json:"failed_units,omitempty"`
	// RestartingUnits lists services whose systemd-tracked restart counter
	// increased during the sampling window -- a real-time signal, unlike
	// the counter's raw cumulative-since-boot value, which would flag any
	// unit that has ever restarted as perpetually suspicious. A unit using
	// Restart=always crash-looping never appears in FailedUnits, since
	// systemd keeps restarting it; this is how that case still surfaces.
	RestartingUnits []SystemdUnitRestart `json:"restarting_units,omitempty"`
}

// SystemdUnitRestart is one unit that restarted during the sample.
type SystemdUnitRestart struct {
	Unit          string `json:"unit"`
	RestartsDelta uint64 `json:"restarts_delta"`
}

type Kernel struct {
	Available bool       `json:"available"`
	Events    []LogEvent `json:"events,omitempty"`
}

// HardwareErrors exposes controller-level EDAC counters. They are cumulative
// since boot; a nonzero count is evidence to correlate with kernel logs, not
// a sampled incident by itself.
type HardwareErrors struct {
	Available   bool                      `json:"available"`
	Controllers []HardwareErrorController `json:"controllers,omitempty"`
}

type HardwareErrorController struct {
	Name                string `json:"name"`
	CorrectableErrors   uint64 `json:"correctable_errors"`
	UncorrectableErrors uint64 `json:"uncorrectable_errors"`
}

// Disk values are normalized from /proc/diskstats for the sampling window.
// Throughput and operation counts are deltas; in_flight is a final gauge.
type Disk struct {
	SampleDurationSeconds float64 `json:"sample_duration_seconds,omitempty"`
	Name                  string  `json:"name"`
	Rotational            bool    `json:"rotational,omitempty"`
	Reads                 uint64  `json:"reads_delta"`
	Writes                uint64  `json:"writes_delta"`
	ReadBytes             uint64  `json:"read_bytes_delta"`
	WriteBytes            uint64  `json:"write_bytes_delta"`
	DiscardBytes          uint64  `json:"discard_bytes_delta,omitempty"`
	IOTimeSeconds         float64 `json:"io_time_seconds_delta"`
	WeightedIOTimeSeconds float64 `json:"weighted_io_time_seconds_delta"`
	InFlight              uint64  `json:"in_flight"`
	Utilization           float64 `json:"utilization"`
	AverageQueueDepth     float64 `json:"average_queue_depth"`
	AverageLatencyMillis  float64 `json:"average_latency_millis,omitempty"`
}

// TCP combines sampled protocol counters with current socket gauges. All
// fields ending in Delta are changes observed in the sampling window.
type TCP struct {
	SegmentsIn            uint64 `json:"segments_in_delta"`
	SegmentsOut           uint64 `json:"segments_out_delta"`
	RetransmittedSegments uint64 `json:"retransmitted_segments_delta"`
	ActiveOpens           uint64 `json:"active_opens_delta"`
	PassiveOpens          uint64 `json:"passive_opens_delta"`
	AttemptFails          uint64 `json:"attempt_fails_delta"`
	EstablishmentResets   uint64 `json:"establishment_resets_delta"`
	ListenOverflows       uint64 `json:"listen_overflows_delta"`
	ListenDrops           uint64 `json:"listen_drops_delta"`
	UDPInErrors           uint64 `json:"udp_in_errors_delta"`
	// IP-level counters sit beside the TCP ones because this struct carries the
	// host-wide kernel network counters read from /proc/net, not TCP alone --
	// UDPInErrors has the same origin. Reassembly and fragmentation failures
	// are the local evidence a path-MTU problem leaves behind.
	IPReassemblyFailures    uint64 `json:"ip_reassembly_failures_delta"`
	IPFragmentationFailures uint64 `json:"ip_fragmentation_failures_delta"`
	CurrentEstablished      uint64 `json:"current_established"`
	TimeWaitSockets         uint64 `json:"time_wait_sockets"`
	OrphanSockets           uint64 `json:"orphan_sockets"`
}

// DeviceHealth intentionally contains only vendor-independent health facts.
// A nil OverallPassed means the command or device did not expose that field.
type DeviceHealth struct {
	Device             string   `json:"device"`
	Kind               string   `json:"kind"`
	OverallPassed      *bool    `json:"overall_passed,omitempty"`
	CriticalWarning    uint64   `json:"critical_warning,omitempty"`
	TemperatureC       float64  `json:"temperature_celsius,omitempty"`
	AvailableSpare     float64  `json:"available_spare_fraction,omitempty"`
	PercentageUsed     float64  `json:"percentage_used_fraction,omitempty"`
	MediaErrors        uint64   `json:"media_errors,omitempty"`
	PendingSectors     uint64   `json:"pending_sectors,omitempty"`
	Uncorrectable      uint64   `json:"uncorrectable_sectors,omitempty"`
	ReallocatedSectors uint64   `json:"reallocated_sectors,omitempty"`
	Notes              []string `json:"notes,omitempty"`
}

type TimeSync struct {
	Available    bool     `json:"available"`
	Service      string   `json:"service,omitempty"`
	Synchronized *bool    `json:"synchronized,omitempty"`
	NTPEnabled   *bool    `json:"ntp_enabled,omitempty"`
	OffsetMillis *float64 `json:"offset_millis,omitempty"`
	Stratum      int      `json:"stratum,omitempty"`
}

// Conntrack carries sampled netfilter drop counters. The table's size and its
// ceiling are gauges and stay under Resources; these are counters and are only
// meaningful across the sampling window, because a lifetime total would report
// a burst from weeks ago as though it were happening now.
type Conntrack struct {
	Drops        uint64 `json:"drops_delta"`
	EarlyDrops   uint64 `json:"early_drops_delta"`
	InsertFailed uint64 `json:"insert_failed_delta"`
}

type Resources struct {
	OpenFiles        uint64 `json:"open_files,omitempty"`
	OpenFilesMaximum uint64 `json:"open_files_maximum,omitempty"`
	// Processes is the kernel's task count, which includes threads.
	Processes uint64 `json:"processes,omitempty"`
	// ProcessesMaximum is pid_max: the highest PID value, not a task limit.
	ProcessesMaximum uint64 `json:"processes_maximum,omitempty"`
	// ThreadsMaximum is threads-max, the ceiling Processes actually approaches.
	ThreadsMaximum   uint64 `json:"threads_maximum,omitempty"`
	Conntrack        uint64 `json:"conntrack,omitempty"`
	ConntrackMaximum uint64 `json:"conntrack_maximum,omitempty"`
	// The kernel exposes no global inotify watch count, so only the limits are
	// reported; they are capacity facts rather than a utilization signal.
	InotifyWatchesMax   uint64 `json:"inotify_watches_maximum,omitempty"`
	InotifyInstancesMax uint64 `json:"inotify_instances_maximum,omitempty"`
	EphemeralPortLow    uint64 `json:"ephemeral_port_low,omitempty"`
	EphemeralPortHigh   uint64 `json:"ephemeral_port_high,omitempty"`
	// Socket table ceilings. The matching current values are counters and live
	// under TCP, so the comparison is made in analysis rather than here.
	TimeWaitMaximum uint64 `json:"time_wait_maximum,omitempty"`
	OrphanMaximum   uint64 `json:"orphan_maximum,omitempty"`
	// ListenBacklogMaximum is net.core.somaxconn, the ceiling a listener's
	// requested backlog is capped to. It turns a listen-overflow finding from
	// an observation into an actionable number.
	ListenBacklogMaximum uint64 `json:"listen_backlog_maximum,omitempty"`
}

// Privileges is coverage metadata, not a health signal. It explains checks
// omitted due to user identity, capabilities, or environment restrictions.
type Privileges struct {
	IsRoot          bool     `json:"is_root"`
	ReducedCoverage []string `json:"reduced_coverage,omitempty"`
}

// Security contains read-only host security and maintenance observations.
// SELinux is "enforcing", "permissive", or "unknown". AppArmor is
// "enabled", "disabled", or "unknown". Unknown means the relevant kernel
// interface was unavailable or could not be read; it is not a policy state.
type Security struct {
	Available bool `json:"available"`
	// JournalWindow names the interval the journal-derived counts cover, so a
	// consumer never has to guess what FailedAuthAttempts is counted over.
	JournalWindow      string                `json:"journal_window,omitempty"`
	RebootRequired     *bool                 `json:"reboot_required,omitempty"`
	RebootFromPackages bool                  `json:"reboot_from_packages,omitempty"`
	KernelTainted      *bool                 `json:"kernel_tainted,omitempty"`
	KernelTaintMask    uint64                `json:"kernel_taint_mask,omitempty"`
	KernelTaintModules []string              `json:"kernel_taint_modules,omitempty"`
	SELinux            string                `json:"selinux"`
	AppArmor           string                `json:"apparmor"`
	Vulnerabilities    []KernelVulnerability `json:"kernel_vulnerabilities,omitempty"`
	FailedAuthAttempts *uint64               `json:"failed_auth_attempts,omitempty"`
	ActiveSessions     *uint64               `json:"active_sessions,omitempty"`
	SELinuxDenials     *uint64               `json:"selinux_denials,omitempty"`
	AppArmorDenials    *uint64               `json:"apparmor_denials,omitempty"`
	CoreDumps          *uint64               `json:"core_dumps,omitempty"`
	CrashArtifacts     []string              `json:"crash_artifacts,omitempty"`
}

type KernelVulnerability struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// CgroupV2 describes the cgroup containing glimpse itself.  Limit values are
// nil when the controller is not enabled or its value is "max". Counter names
// ending in Delta are changes during this report's sampling window; this keeps
// historical cgroup events from becoming spurious current-health findings.
type CgroupV2 struct {
	Available                bool    `json:"available"`
	Path                     string  `json:"path,omitempty"`
	Containerized            bool    `json:"containerized"`
	MemoryCurrentBytes       uint64  `json:"memory_current_bytes,omitempty"`
	MemoryMaxBytes           *uint64 `json:"memory_max_bytes,omitempty"`
	MemorySwapCurrentBytes   uint64  `json:"memory_swap_current_bytes,omitempty"`
	MemorySwapMaxBytes       *uint64 `json:"memory_swap_max_bytes,omitempty"`
	MemoryOOMDelta           uint64  `json:"memory_oom_delta,omitempty"`
	MemoryOOMKillDelta       uint64  `json:"memory_oom_kill_delta,omitempty"`
	CPUUsageSecondsDelta     float64 `json:"cpu_usage_seconds_delta,omitempty"`
	CPUThrottledSecondsDelta float64 `json:"cpu_throttled_seconds_delta,omitempty"`
	PIDsCurrent              uint64  `json:"pids_current,omitempty"`
	PIDsMax                  *uint64 `json:"pids_max,omitempty"`
}

// ContainerRuntime is an optional, runtime-scoped observation. A missing
// runtime or denied socket access is represented in Collection, not here as a
// failed health state.
type ContainerRuntime struct {
	Runtime         string      `json:"runtime"`
	Containers      []Container `json:"containers,omitempty"`
	LogsChecked     int         `json:"logs_checked,omitempty"`
	LogCandidates   int         `json:"log_candidates,omitempty"`
	LogWindow       string      `json:"log_window,omitempty"`
	LogCheckLimited bool        `json:"log_check_limited,omitempty"`
}

// Container is deliberately a small common denominator for Docker and Podman.
// RestartCount is a sample-window delta rather than a lifetime counter.
type Container struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	State            string `json:"state"`
	Healthy          *bool  `json:"healthy,omitempty"`
	RestartCount     uint64 `json:"restart_count_delta,omitempty"`
	OOMKilled        bool   `json:"oom_killed,omitempty"`
	HasRestartPolicy bool   `json:"has_restart_policy,omitempty"`
	// LogEvents contains every distinct, explicitly classified log match from
	// the bounded log read (maxLogBytes per container). It is empty when no
	// actionable entries were found or logs were unavailable; a denied
	// runtime is represented in Collection instead.
	LogEvents []LogEvent `json:"log_events,omitempty"`
}

// ZFSPool contains stable facts from one zpool status observation. Error
// counters are current pool values, not sampled deltas; a non-ONLINE health or
// permanent data errors is therefore the strongest signal.
type ZFSPool struct {
	Name            string `json:"name"`
	Health          string `json:"health"`
	ReadErrors      uint64 `json:"read_errors,omitempty"`
	WriteErrors     uint64 `json:"write_errors,omitempty"`
	ChecksumErrors  uint64 `json:"checksum_errors,omitempty"`
	ScanState       string `json:"scan_state,omitempty"`
	PermanentErrors bool   `json:"permanent_errors,omitempty"`
}

type SoftwareRAID struct {
	Device         string `json:"device"`
	Level          string `json:"level"`
	State          string `json:"state"`
	ResyncProgress string `json:"resync_progress,omitempty"`
	ReadOnly       bool   `json:"read_only,omitempty"`
}
type LVM struct {
	PhysicalVolumes []LVMPhysicalVolume `json:"physical_volumes,omitempty"`
	VolumeGroups    []LVMVolumeGroup    `json:"volume_groups,omitempty"`
	LogicalVolumes  []LVMLogicalVolume  `json:"logical_volumes,omitempty"`
}
type LVMPhysicalVolume struct {
	Name      string `json:"name"`
	Group     string `json:"group"`
	Attr      string `json:"attr"`
	SizeBytes uint64 `json:"size_bytes"`
	FreeBytes uint64 `json:"free_bytes"`
}
type LVMVolumeGroup struct {
	Name      string `json:"name"`
	Attr      string `json:"attr"`
	SizeBytes uint64 `json:"size_bytes"`
	FreeBytes uint64 `json:"free_bytes"`
	// NeedsReview is decided by the collector from the positional attribute
	// bits, so analysis and rendering share one interpretation of them.
	NeedsReview  bool   `json:"needs_review,omitempty"`
	ReviewReason string `json:"needs_review_reason,omitempty"`
}
type LVMLogicalVolume struct {
	Name         string `json:"name"`
	Group        string `json:"group"`
	Attr         string `json:"attr"`
	SizeBytes    uint64 `json:"size_bytes"`
	NeedsReview  bool   `json:"needs_review,omitempty"`
	ReviewReason string `json:"needs_review_reason,omitempty"`
}
type MountCheck struct {
	MountPoint  string   `json:"mount_point"`
	Source      string   `json:"source"`
	FSType      string   `json:"filesystem_type"`
	Options     []string `json:"options,omitempty"`
	Persistent  bool     `json:"persistent"`
	Active      bool     `json:"active"`
	ActiveKnown bool     `json:"active_known"`
}

// Trend is a bounded, in-memory sparkline-ready series. Values are normalized
// to the declared unit and have no persistence or historical implication.
type Trend struct {
	Name   string    `json:"name"`
	Unit   string    `json:"unit"`
	Values []float64 `json:"values"`
}

// LogEvent is one classified log record. AgeSeconds is the record's age at
// collection time when the source exposed a timestamp; it is nil when the age
// is unknown, which analysis must not read as "recent".
type LogEvent struct {
	Kind       string   `json:"kind"`
	Message    string   `json:"message"`
	AgeSeconds *float64 `json:"age_seconds,omitempty"`
}

type Evidence struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type Finding struct {
	ID          string     `json:"id"`
	Severity    Severity   `json:"severity"`
	Category    string     `json:"category"`
	Title       string     `json:"title"`
	Summary     string     `json:"summary"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	Suggestion  string     `json:"suggestion,omitempty"`
	ScoreImpact int        `json:"score_impact"`
}

type Score struct {
	Value  int      `json:"value"`
	Status Severity `json:"status"`
	Label  string   `json:"label"`
}

type CollectionStatus struct {
	Collector string `json:"collector"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
}
