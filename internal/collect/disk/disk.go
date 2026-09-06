// Package disk reads sampled block-device activity from procfs and sysfs.
package disk

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const sectorBytes = 512

// Counters are the useful cumulative fields in /proc/diskstats. Sector counts
// use Linux's fixed 512-byte diskstats unit, irrespective of device block size.
type Counters struct {
	Reads, ReadsMerged, ReadSectors, ReadMillis            uint64
	Writes, WritesMerged, WriteSectors, WriteMillis        uint64
	InFlight, IOMillis, WeightedIOMillis                   uint64
	Discards, DiscardMerged, DiscardSectors, DiscardMillis uint64
	Flushes, FlushMillis                                   uint64
}

type Device struct {
	Name         string
	Major, Minor uint64
	Counters     Counters
	Rotational   *bool
}

// Snapshot is a private point-in-time observation used to derive deltas.
type Snapshot struct {
	At      time.Time
	Devices []Device
}

// Delta contains window-local block-device facts. Rates deliberately remain
// derivable from counters and Duration so presentation and analysis can choose
// their own units without losing precision.
type Delta struct {
	Name             string
	Duration         time.Duration
	Reads, Writes    uint64
	ReadBytes        uint64
	WriteBytes       uint64
	ReadMillis       uint64
	WriteMillis      uint64
	IOMillis         uint64
	WeightedIOMillis uint64
	InFlight         uint64 // final instantaneous gauge
	Discards         uint64
	DiscardBytes     uint64
	DiscardMillis    uint64
	Flushes          uint64
	FlushMillis      uint64
	Rotational       *bool
}

// ParseDiskStats parses Linux /proc/diskstats, accepting optional discard and
// flush fields on older kernels. It does not filter partitions: that requires
// sysfs topology and is performed by ReadSnapshot.
func ParseDiskStats(r io.Reader) ([]Device, error) {
	// A record this parser cannot read is skipped rather than failing the whole
	// file: one unrecognized row must not remove every device from the report.
	// An input with no readable row at all is still an error.
	s := bufio.NewScanner(r)
	devices := make([]Device, 0)
	for line := 1; s.Scan(); line++ {
		f := strings.Fields(s.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) < 14 || f[2] == "" {
			continue
		}
		major, err := parseUint(f[0], "major")
		if err != nil {
			continue
		}
		minor, err := parseUint(f[1], "minor")
		if err != nil {
			continue
		}
		values := make([]uint64, len(f)-3)
		malformed := false
		for i, value := range f[3:] {
			values[i], err = parseUint(value, "counter")
			if err != nil {
				malformed = true
				break
			}
		}
		if malformed {
			continue
		}
		c := Counters{Reads: values[0], ReadsMerged: values[1], ReadSectors: values[2], ReadMillis: values[3], Writes: values[4], WritesMerged: values[5], WriteSectors: values[6], WriteMillis: values[7], InFlight: values[8], IOMillis: values[9], WeightedIOMillis: values[10]}
		if len(values) >= 15 {
			c.Discards, c.DiscardMerged, c.DiscardSectors, c.DiscardMillis = values[11], values[12], values[13], values[14]
		}
		if len(values) >= 17 {
			c.Flushes, c.FlushMillis = values[15], values[16]
		}
		devices = append(devices, Device{Name: f[2], Major: major, Minor: minor, Counters: c})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, errors.New("diskstats: no devices")
	}
	return devices, nil
}

func parseUint(s, label string) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s %q: %w", label, s, err)
	}
	return v, nil
}

// ReadSnapshot reads procfs and enriches whole disks with optional sysfs
// metadata. Missing sysfs data is normal in containers and does not fail the
// rootless collector.
func ReadSnapshot(ctx context.Context, procRoot, sysRoot string) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	if sysRoot == "" {
		sysRoot = "/sys"
	}
	f, err := os.Open(filepath.Join(procRoot, "diskstats"))
	if err != nil {
		return Snapshot{}, err
	}
	defer f.Close()
	devices, err := ParseDiskStats(f)
	if err != nil {
		return Snapshot{}, err
	}

	physical := make([]Device, 0, len(devices))
	for _, device := range devices {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		base := filepath.Join(sysRoot, "block", device.Name)
		info, err := os.Stat(base)
		if err != nil {
			// Without sysfs metadata, retain the device when its name is one
			// that conventionally denotes a physical disk, rather than turning
			// an optional capability gap into a missing device. A hidden or
			// partially populated /sys must not silently drop drives.
			if physicalDeviceName(device.Name) {
				physical = append(physical, device)
			}
			continue
		}
		if !info.IsDir() {
			continue
		}
		if value, err := readUint(filepath.Join(base, "queue/rotational")); err == nil {
			v := value != 0
			device.Rotational = &v
		}
		// Device-mapper, loop, md, ram, and zram entries are virtual layers.
		// Their I/O is also charged to the backing disk, so showing them creates
		// duplicate activity and hides the drive a user can actually identify.
		if physicalDeviceName(device.Name) || sysfsHasPhysicalDevice(base) {
			physical = append(physical, device)
		}
	}
	// When sysfs is hidden, retain only names that conventionally represent
	// physical disks. Never fall back to all procfs entries: that would bring
	// loop and device-mapper duplicates back into the normal report.
	if len(physical) == 0 {
		for _, device := range devices {
			if physicalDeviceName(device.Name) {
				physical = append(physical, device)
			}
		}
	}
	sort.Slice(physical, func(i, j int) bool { return physical[i].Name < physical[j].Name })
	return Snapshot{At: time.Now(), Devices: physical}, nil
}

func physicalDeviceName(name string) bool {
	return strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "hd") ||
		strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "xvd") ||
		strings.HasPrefix(name, "nvme") || strings.HasPrefix(name, "mmcblk")
}

func sysfsHasPhysicalDevice(base string) bool {
	info, err := os.Stat(filepath.Join(base, "device"))
	return err == nil && info.IsDir()
}

func readUint(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

// Between derives sampling-window counters. Counter reset or device
// replacement produces zero growth, avoiding fabricated huge deltas.
func Between(first, last Snapshot) []Delta {
	previous := make(map[string]Device, len(first.Devices))
	for _, device := range first.Devices {
		previous[device.Name] = device
	}
	duration := last.At.Sub(first.At)
	if duration < 0 {
		duration = 0
	}
	result := make([]Delta, 0, len(last.Devices))
	for _, device := range last.Devices {
		before, exists := previous[device.Name]
		if !exists || before.Major != device.Major || before.Minor != device.Minor {
			continue
		}
		d := diff(before.Counters, device.Counters)
		result = append(result, Delta{Name: device.Name, Duration: duration, Reads: d.Reads, Writes: d.Writes, ReadBytes: sectorsToBytes(d.ReadSectors), WriteBytes: sectorsToBytes(d.WriteSectors), ReadMillis: d.ReadMillis, WriteMillis: d.WriteMillis, IOMillis: d.IOMillis, WeightedIOMillis: d.WeightedIOMillis, InFlight: device.Counters.InFlight, Discards: d.Discards, DiscardBytes: sectorsToBytes(d.DiscardSectors), DiscardMillis: d.DiscardMillis, Flushes: d.Flushes, FlushMillis: d.FlushMillis, Rotational: device.Rotational})
	}
	return result
}

func sectorsToBytes(sectors uint64) uint64 {
	if sectors > ^uint64(0)/sectorBytes {
		return ^uint64(0)
	}
	return sectors * sectorBytes
}

func diff(before, after Counters) Counters {
	d := func(a, b uint64) uint64 {
		if b < a {
			return 0
		}
		return b - a
	}
	return Counters{Reads: d(before.Reads, after.Reads), ReadsMerged: d(before.ReadsMerged, after.ReadsMerged), ReadSectors: d(before.ReadSectors, after.ReadSectors), ReadMillis: d(before.ReadMillis, after.ReadMillis), Writes: d(before.Writes, after.Writes), WritesMerged: d(before.WritesMerged, after.WritesMerged), WriteSectors: d(before.WriteSectors, after.WriteSectors), WriteMillis: d(before.WriteMillis, after.WriteMillis), InFlight: after.InFlight, IOMillis: d(before.IOMillis, after.IOMillis), WeightedIOMillis: d(before.WeightedIOMillis, after.WeightedIOMillis), Discards: d(before.Discards, after.Discards), DiscardMerged: d(before.DiscardMerged, after.DiscardMerged), DiscardSectors: d(before.DiscardSectors, after.DiscardSectors), DiscardMillis: d(before.DiscardMillis, after.DiscardMillis), Flushes: d(before.Flushes, after.Flushes), FlushMillis: d(before.FlushMillis, after.FlushMillis)}
}
