package storagehealth

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCollectorUsesNVMeAndMakesFailureOptional(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "block", "nvme0n1"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := New()
	c.SysRoot = root
	c.lookPath = func(name string) (string, error) {
		if name == "nvme" {
			return "/usr/bin/nvme", nil
		}
		return "", errors.New("missing")
	}
	c.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(`{"critical_warning":0,"temperature":35,"available_spare":99}`), nil
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(data.DeviceHealth) != 1 || data.DeviceHealth[0].AvailableSpare != .99 {
		t.Fatalf("got %#v", data.DeviceHealth)
	}
}

func TestCollectorSkipsVirtualOnlyDisks(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "block", "vda"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := New()
	c.SysRoot = root
	called := false
	c.lookPath = func(string) (string, error) { called = true; return "/usr/bin/smartctl", nil }
	data, err := c.Collect(context.Background())
	if err != nil || called || len(data.DeviceHealth) != 0 || len(data.Diagnostics) != 0 {
		t.Fatalf("virtual disk was probed: data=%+v err=%v called=%v", data, err, called)
	}
}

func TestCollectorBoundsTotalCommandScan(t *testing.T) {
	// The sweep must finish within its budget however many devices exist, and
	// must say which devices it could not reach. Probing them serially meant a
	// multi-bay host silently stopped after the first two or three disks.
	root := t.TempDir()
	devices := []string{"sda", "sdb", "sdc", "sdd", "sde", "sdf", "sdg", "sdh"}
	for _, device := range devices {
		if err := os.MkdirAll(filepath.Join(root, "block", device), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	c := New()
	c.SysRoot, c.Timeout, c.MaxDuration = root, time.Second, 40*time.Millisecond
	c.lookPath = func(name string) (string, error) {
		if name == "smartctl" {
			return "/usr/bin/smartctl", nil
		}
		return "", errors.New("missing")
	}
	var mu sync.Mutex
	calls := 0
	c.run = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	started := time.Now()
	data, err := c.Collect(context.Background())
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("scan overran its budget: %s", elapsed)
	}
	if calls == 0 || calls > len(devices) {
		t.Fatalf("calls=%d", calls)
	}
	if len(data.Diagnostics) == 0 {
		t.Fatal("an incomplete device scan left no diagnostic")
	}
	if coverage := data.DeviceHealthCoverage; coverage == nil || coverage.DevicesEligible != len(devices) || coverage.DevicesChecked != 0 || !coverage.Limited || coverage.Reason != "scan deadline" {
		t.Fatalf("coverage=%+v", coverage)
	}
}

func TestCollectorReportsZeroSuccessWhenHealthToolsAreUnavailable(t *testing.T) {
	root := t.TempDir()
	for _, device := range []string{"sda", "sdb"} {
		if err := os.MkdirAll(filepath.Join(root, "block", device), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	c := New()
	c.SysRoot = root
	c.lookPath = func(string) (string, error) { return "", errors.New("missing") }
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if coverage := data.DeviceHealthCoverage; coverage == nil || coverage.DevicesEligible != 2 || coverage.DevicesChecked != 0 || !coverage.Limited || coverage.Reason != "SMART/NVMe tools unavailable" {
		t.Fatalf("coverage=%+v", coverage)
	}
}

func TestScanBudgetScalesWithDeviceCount(t *testing.T) {
	// One fixed ten-second budget for any number of disks is what stopped a
	// twelve-bay host after two or three of them.
	if got := scanBudget(1, 5*time.Second); got != scanTimeout {
		t.Fatalf("single device budget=%s", got)
	}
	if scanBudget(12, 5*time.Second) <= scanTimeout {
		t.Fatal("budget did not grow with device count")
	}
	if got := scanBudget(200, 5*time.Second); got != maxScanTime {
		t.Fatalf("budget not capped: %s", got)
	}
}

func TestPhysicalDevice(t *testing.T) {
	for _, name := range []string{"sda", "hda", "nvme0n1"} {
		if !physicalDevice(name) {
			t.Errorf("%s not physical", name)
		}
	}
	for _, name := range []string{"vda", "xvda", "dm-0", "md0", "ram0"} {
		if physicalDevice(name) {
			t.Errorf("%s physical", name)
		}
	}
}

func TestCollectorDiscoversSymlinkedBlockDevice(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "devices", "sda")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "block"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "block", "sda")); err != nil {
		t.Fatal(err)
	}
	c := New()
	c.SysRoot = root
	devices, err := c.devices()
	if err != nil || len(devices) != 1 || devices[0] != "sda" {
		t.Fatalf("got %v, %v", devices, err)
	}
}

func TestToModelKeepsNonThresholdCountersAsNotes(t *testing.T) {
	got := toModel(Device{CRCErrors: 3, UnsafeShutdowns: 4})
	if len(got.Notes) != 2 || got.Notes[0] != "CRC errors: 3" || got.Notes[1] != "unsafe shutdowns: 4" {
		t.Fatalf("got %#v", got.Notes)
	}
}

func TestSmartExitHelper(t *testing.T) {
	if code := os.Getenv("GLIMPSE_TEST_SMART_EXIT"); code != "" {
		n, _ := strconv.Atoi(code)
		os.Exit(n)
	}
}

func TestSmartHealthExitRetainsFailureFacts(t *testing.T) {
	for _, code := range []string{"8", "2", "4"} {
		t.Run(code, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "block", "sda"), 0755); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSmartExitHelper$")
			command.Env = append(os.Environ(), "GLIMPSE_TEST_SMART_EXIT="+code)
			runErr := command.Run()
			c := New()
			c.SysRoot = root
			c.lookPath = func(name string) (string, error) {
				if name == "smartctl" {
					return name, nil
				}
				return "", errors.New("missing")
			}
			c.run = func(context.Context, string, ...string) ([]byte, error) {
				return []byte(`{"smart_status":{"passed":false}}`), runErr
			}
			data, err := c.Collect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if code == "8" {
				if len(data.DeviceHealth) != 1 || data.DeviceHealth[0].OverallPassed == nil || *data.DeviceHealth[0].OverallPassed {
					t.Fatalf("lost health failure: %+v", data)
				}
			} else if len(data.DeviceHealth) != 0 || len(data.Diagnostics) == 0 || strings.Contains(data.Diagnostics[0].Detail, "exit status") {
				t.Fatalf("execution failure was not explained clearly: %+v", data)
			} else if code == "2" && !strings.Contains(data.Diagnostics[0].Detail, "could not open the device") {
				t.Fatalf("device access failure was not explained: %+v", data)
			} else if code == "4" && !strings.Contains(data.Diagnostics[0].Detail, "rejected the SMART query") {
				t.Fatalf("unsupported SMART query was not explained: %+v", data)
			}
		})
	}
}
