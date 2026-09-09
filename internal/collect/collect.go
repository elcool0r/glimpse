// Package collect defines the concurrency-safe collector boundary.
package collect

import (
	"context"

	"github.com/elcool0r/glimpse/internal/model"
)

// Data contains one or more normalized metric categories. A collector must
// only populate categories it owns. All values are facts, never findings.
type Data struct {
	// Diagnostics records nonfatal gaps independently of health observations.
	Diagnostics []model.CollectionStatus

	// Snapshot is collector-private observation state. It is deliberately not
	// serialized; DeltaCollector implementations use it to derive sampled
	// counters from the two collection boundaries.
	Snapshot             any
	CPU                  *model.CPU
	Memory               *model.Memory
	Pressure             *model.Pressure
	Filesystems          []model.Filesystem
	Network              []model.Network
	Thermal              []model.Thermal
	Processes            *model.Processes
	Systemd              *model.Systemd
	Kernel               *model.Kernel
	Disks                []model.Disk
	TCP                  *model.TCP
	Conntrack            *model.Conntrack
	DeviceHealth         []model.DeviceHealth
	DeviceHealthCoverage *model.DeviceHealthCoverage
	TimeSync             *model.TimeSync
	Resources            *model.Resources
	Privileges           *model.Privileges
	CgroupV2             *model.CgroupV2
	Containers           []model.ContainerRuntime
	ZFSPools             []model.ZFSPool
	SoftwareRAID         []model.SoftwareRAID
	LVM                  *model.LVM
	MountChecks          []model.MountCheck
	Security             *model.Security
	NetworkState         *model.NetworkState
	DNSResolution        *model.DNSResolution
	GatewayCheck         *model.GatewayCheck
	PathMTUCheck         *model.PathMTUCheck
	HTTPCheck            *model.HTTPCheck
	ICMPCheck            *model.ICMPCheck
	IPv6Check            *model.IPv6Check
	DeletedFiles         *model.DeletedFiles
	Hardware             *model.HardwareErrors
	Trends               []model.Trend
	PackageActivity      []model.PackageActivity
	Logins               []model.LoginEvent
	SudoCommands         []model.SudoEvent
}

// Collector reads one coherent observation. Sampling invokes Collect at the
// beginning and end of the window. Collectors must be safe for serial reuse;
// they must not retain mutable data between calls.
type Collector interface {
	Name() string
	Collect(context.Context) (Data, error)
}

// DeltaCollector optionally derives window metrics from two observations.
// The app invokes it after the final collection. Collectors that only expose
// gauges need only implement Collector.
//
// An implementation that cannot derive counters must still return the final
// observation's gauges alongside its error, marking them unsampled where the
// model can express that. Returning an empty Data with an error erases metrics
// that were collected successfully.
type DeltaCollector interface {
	Collector
	Delta(first, last Data) (Data, error)
}

// StaticCollector marks a collector whose observation is a gauge rather than a
// counter boundary, so only the final collection is used. The application
// skips its baseline collection entirely.
//
// This matters because most optional integrations are in this class: without
// the marker, every smartctl, journalctl, LVM, ss and zpool invocation runs
// twice per report and the first result is discarded by merge, doubling
// external command cost against a fixed overhead budget.
type StaticCollector interface {
	Collector
	// Static is a marker; it is never called.
	Static()
}

// TrendCollector is an optional extension for inexpensive dynamic collectors.
// The application records bounded intermediate observations and asks the
// collector to convert them to sparkline-ready trends after sampling.
type TrendCollector interface {
	Collector
	Trends(samples []Data) []model.Trend
}
