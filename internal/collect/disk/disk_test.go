package disk

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
)

func TestParseDiskStatsAndBetween(t *testing.T) {
	const input = "8 0 sda 10 1 20 30 40 2 60 70 3 80 90 4 5 6 7 8 9\n"
	devices, err := ParseDiskStats(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Counters.Flushes != 8 || devices[0].Counters.DiscardSectors != 6 {
		t.Fatalf("unexpected parsed device: %#v", devices)
	}
	before := Snapshot{At: time.Unix(100, 0), Devices: devices}
	afterDevice := devices[0]
	afterDevice.Counters.Reads, afterDevice.Counters.Writes = 15, 43
	afterDevice.Counters.ReadSectors, afterDevice.Counters.WriteSectors = 30, 80
	afterDevice.Counters.ReadMillis, afterDevice.Counters.WriteMillis = 40, 100
	afterDevice.Counters.IOMillis, afterDevice.Counters.WeightedIOMillis = 100, 140
	after := Snapshot{At: time.Unix(102, 0), Devices: []Device{afterDevice}}
	delta := Between(before, after)
	if len(delta) != 1 || delta[0].Reads != 5 || delta[0].Writes != 3 || delta[0].ReadBytes != 5120 || delta[0].WriteBytes != 10240 || delta[0].IOMillis != 20 {
		t.Fatalf("unexpected delta: %#v", delta)
	}
}

func TestReadSnapshotKeepsPhysicalDisksAndDropsVirtualLayers(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	sysRoot := filepath.Join(root, "sys")
	if err := os.MkdirAll(filepath.Join(procRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "diskstats"), []byte("8 0 sda 1 0 1 1 1 0 1 1 0 1 1\n252 1 dm-1 1 0 1 1 1 0 1 1 0 1 1\n7 0 loop0 1 0 1 1 1 0 1 1 0 1 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sda", "dm-1", "loop0"} {
		if err := os.MkdirAll(filepath.Join(sysRoot, "block", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := ReadSnapshot(context.Background(), procRoot, sysRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 || snapshot.Devices[0].Name != "sda" {
		t.Fatalf("got %#v; expected only physical sda", snapshot.Devices)
	}
}

func TestReadSnapshotDropsPartitionsWithoutSysfsTopology(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	sysRoot := filepath.Join(root, "sys")
	if err := os.MkdirAll(procRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	const stats = "8 0 sda 1 0 1 1 1 0 1 1 0 1 1\n8 1 sda1 1 0 1 1 1 0 1 1 0 1 1\n259 0 nvme0n1 1 0 1 1 1 0 1 1 0 1 1\n259 1 nvme0n1p1 1 0 1 1 1 0 1 1 0 1 1\n"
	if err := os.WriteFile(filepath.Join(procRoot, "diskstats"), []byte(stats), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ReadSnapshot(context.Background(), procRoot, sysRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(snapshot.Devices); strings.Join(got, ",") != "nvme0n1,sda" {
		t.Fatalf("devices = %v, want whole disks only", got)
	}
}

func TestPhysicalDeviceNameRejectsPrefixesAndPartitions(t *testing.T) {
	for _, name := range []string{"sda1", "nvme0n1p1", "mmcblk0p1", "xvda1", "not-a-disk"} {
		if physicalDeviceName(name) {
			t.Fatalf("physicalDeviceName(%q) = true, want false", name)
		}
	}
	for _, name := range []string{"sda", "vda", "xvda", "nvme0n1", "mmcblk0"} {
		if !physicalDeviceName(name) {
			t.Fatalf("physicalDeviceName(%q) = false, want true", name)
		}
	}
}

func TestReadSnapshotDropsPartitionFromDeviceTopology(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	sysRoot := filepath.Join(root, "sys")
	if err := os.MkdirAll(filepath.Join(procRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "diskstats"), []byte("8 1 sda1 1 0 1 1 1 0 1 1 0 1 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	partition := filepath.Join(sysRoot, "dev", "block", "8:1", "partition")
	if err := os.MkdirAll(filepath.Dir(partition), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(partition, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ReadSnapshot(context.Background(), procRoot, sysRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 0 {
		t.Fatalf("devices = %#v, want partition excluded", snapshot.Devices)
	}
}

func names(devices []Device) []string {
	result := make([]string, len(devices))
	for i, device := range devices {
		result[i] = device.Name
	}
	return result
}

func TestParseDiskStatsRejectsMalformed(t *testing.T) {
	if _, err := ParseDiskStats(strings.NewReader("8 0 sda 1 2\n")); err == nil {
		t.Fatal("expected malformed input error")
	}
}

func TestCollectorDelta(t *testing.T) {
	first := Snapshot{At: time.Unix(10, 0), Devices: []Device{{Name: "vda", Major: 252, Counters: Counters{Reads: 10, ReadSectors: 10, IOMillis: 500, WeightedIOMillis: 700}}}}
	last := Snapshot{At: time.Unix(12, 0), Devices: []Device{{Name: "vda", Major: 252, Counters: Counters{Reads: 12, ReadSectors: 14, IOMillis: 600, WeightedIOMillis: 900}}}}
	data, err := (Collector{}).Delta(collect.Data{Snapshot: first}, collect.Data{Snapshot: last})
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Disks) != 1 || data.Disks[0].Utilization != .05 || data.Disks[0].AverageQueueDepth != .1 || data.Disks[0].ReadBytes != 2048 {
		t.Fatalf("unexpected disk model: %#v", data.Disks)
	}
}

func TestReadSnapshotCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadSnapshot(ctx, "/definitely/missing", ""); err == nil {
		t.Fatal("expected cancellation")
	}
}

func TestDiskTrends(t *testing.T) {
	samples := []collect.Data{
		{Snapshot: Snapshot{At: time.Unix(1, 0), Devices: []Device{{Name: "vda", Counters: Counters{IOMillis: 10}}}}},
		{Snapshot: Snapshot{At: time.Unix(2, 0), Devices: []Device{{Name: "vda", Counters: Counters{IOMillis: 510}}}}},
	}
	trends := (Collector{}).Trends(samples)
	if len(trends) != 1 || trends[0].Name != "disk.vda.utilization" || len(trends[0].Values) != 1 || trends[0].Values[0] != .5 {
		t.Fatalf("unexpected trends: %#v", trends)
	}
}
