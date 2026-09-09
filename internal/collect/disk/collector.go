package disk

import (
	"context"
	"errors"
	"math"
	"sort"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

// Collector captures rootless /proc/diskstats observations. SysRoot metadata
// is optional, so it remains useful in containers with a restricted /sys.
type Collector struct{ ProcRoot, SysRoot string }

func (Collector) Name() string { return "disk" }

func (c Collector) Collect(ctx context.Context) (collect.Data, error) {
	snapshot, err := ReadSnapshot(ctx, c.ProcRoot, c.SysRoot)
	if err != nil {
		return collect.Data{}, err
	}
	return collect.Data{Snapshot: snapshot}, nil
}

// Trends emits bounded per-device utilization samples from the same snapshots
// used by the normal collector. A device absent from an interval is omitted;
// no zero is invented for hot-removed or newly discovered devices.
func (Collector) Trends(samples []collect.Data) []model.Trend {
	if len(samples) < 2 {
		return nil
	}
	values := make(map[string][]float64)
	for i := 1; i < len(samples); i++ {
		first, firstOK := samples[i-1].Snapshot.(Snapshot)
		last, lastOK := samples[i].Snapshot.(Snapshot)
		if !firstOK || !lastOK {
			continue
		}
		for _, delta := range Between(first, last) {
			duration := delta.Duration.Seconds()
			if duration <= 0 {
				continue
			}
			values[delta.Name] = append(values[delta.Name], math.Min(1, float64(delta.IOMillis)/1000/duration))
		}
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	trends := make([]model.Trend, 0, len(names))
	for _, name := range names {
		trends = append(trends, model.Trend{Name: "disk." + name + ".utilization", Unit: "fraction", Values: values[name]})
	}
	return trends
}

func (Collector) Delta(first, last collect.Data) (collect.Data, error) {
	end, endOK := last.Snapshot.(Snapshot)
	if !endOK {
		return collect.Data{}, errors.New("disk: invalid final snapshot")
	}
	start, startOK := first.Snapshot.(Snapshot)
	if !startOK {
		// The device inventory and in-flight gauge are still valid. Reporting
		// them with a zero interval keeps the disks visible without inventing
		// activity: no rate, utilization or queue rule can fire on zeros.
		return finalGauges(end), errors.New("disk: invalid first snapshot")
	}
	if start.At.IsZero() || end.At.IsZero() || !end.At.After(start.At) {
		return finalGauges(end), errors.New("disk: invalid sampling interval")
	}
	deltas := Between(start, end)
	disks := make([]model.Disk, 0, len(deltas))
	sampled := true
	previous := make(map[string]Device, len(start.Devices))
	for _, device := range start.Devices {
		previous[device.Name] = device
	}
	for _, delta := range deltas {
		ioSeconds := float64(delta.IOMillis) / 1000
		weightedSeconds := float64(delta.WeightedIOMillis) / 1000
		durationSeconds := delta.Duration.Seconds()
		utilization, queueDepth := 0.0, 0.0
		if durationSeconds > 0 {
			utilization = ioSeconds / durationSeconds
			// Kernel accounting can slightly exceed the wall-clock boundary;
			// clamp this presentation-friendly fraction conservatively.
			utilization = math.Min(utilization, 1)
			queueDepth = weightedSeconds / durationSeconds
		}
		operations := delta.Reads + delta.Writes
		latency := 0.0
		if operations > 0 {
			latency = float64(delta.ReadMillis+delta.WriteMillis) / float64(operations)
		}
		rotational := false
		if delta.Rotational != nil {
			rotational = *delta.Rotational
		}
		disks = append(disks, model.Disk{Sampled: &sampled, SampleDurationSeconds: durationSeconds, Name: delta.Name, Rotational: rotational, Reads: delta.Reads, Writes: delta.Writes, ReadBytes: delta.ReadBytes, WriteBytes: delta.WriteBytes, DiscardBytes: delta.DiscardBytes, IOTimeSeconds: ioSeconds, WeightedIOTimeSeconds: weightedSeconds, InFlight: delta.InFlight, Utilization: utilization, AverageQueueDepth: queueDepth, AverageLatencyMillis: latency})
	}
	// A final device without the same baseline identity is still useful
	// inventory, but its interval counters are unavailable for this window.
	unsampled := false
	for _, device := range end.Devices {
		before, exists := previous[device.Name]
		if exists && before.Major == device.Major && before.Minor == device.Minor {
			continue
		}
		rotational := false
		if device.Rotational != nil {
			rotational = *device.Rotational
		}
		disks = append(disks, model.Disk{Sampled: &unsampled, Name: device.Name, Rotational: rotational, InFlight: device.Counters.InFlight})
	}
	return collect.Data{Disks: disks}, nil
}

// finalGauges reports devices without a sampling interval.
func finalGauges(last Snapshot) collect.Data {
	disks := make([]model.Disk, 0, len(last.Devices))
	sampled := false
	for _, device := range last.Devices {
		rotational := false
		if device.Rotational != nil {
			rotational = *device.Rotational
		}
		disks = append(disks, model.Disk{Sampled: &sampled, Name: device.Name, Rotational: rotational, InFlight: device.Counters.InFlight})
	}
	return collect.Data{Disks: disks}
}
