package kernel

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestParseEventsUsesExplicitPatterns(t *testing.T) {
	input := `kernel: generic error is not actionable
kernel: Out of memory: Killed process 99 (worker)
kernel: INFO: task backup:12 blocked for more than 120 seconds.
kernel: blk_update_request: I/O error, dev sda, sector 42
kernel: EXT4-fs error (device sda1): ext4_find_entry:1463
kernel: Hardware Error: CPU 0: Machine Check Event`
	got := ParseEvents(input, time.Now())
	kinds := make([]string, len(got))
	for i, event := range got {
		kinds[i] = event.Kind
	}
	want := []string{"oom", "blocked_task", "io_error", "filesystem_error", "hardware_error"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("got %#v, want %#v", kinds, want)
	}
}

func TestParseEventsRecognizesHighSignalKernelEventsOnce(t *testing.T) {
	input := `kernel: Memory cgroup out of memory: Killed process 12
kernel: Killed process 12 (worker)
kernel: Kernel panic - not syncing: Fatal exception
kernel: BUG: unable to handle kernel NULL pointer dereference
kernel: nvme0: I/O 12 QID 1 timeout, reset controller
kernel: ZFS: pool tank degraded due to an error
kernel: CPU0: Thermal throttling asserted`
	got := ParseEvents(input, time.Now())
	kinds := make([]string, len(got))
	for i, event := range got {
		kinds[i] = event.Kind
	}
	want := []string{"cgroup_oom", "kernel_panic", "kernel_oops", "nvme_error", "zfs_error", "thermal_throttling"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("got %#v, want %#v", kinds, want)
	}
}

func TestUnavailableJournalIsNotAnError(t *testing.T) {
	c := New()
	c.lookPath = func(string) (string, error) { return "", errors.New("missing") }
	data, err := c.Collect(context.Background())
	if err != nil || data.Kernel == nil || data.Kernel.Available {
		t.Fatalf("data=%#v err=%v", data, err)
	}
}

func TestCollectorUsesPortableKernelShortOption(t *testing.T) {
	var args []string
	c := New()
	c.lookPath = func(string) (string, error) { return "journalctl", nil }
	c.run = func(_ context.Context, _ string, got ...string) ([]byte, error) {
		args = got
		return nil, nil
	}
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, arg := range args {
		if arg == "--kernel" {
			t.Fatalf("unsupported option used: %q", args)
		}
	}
	found := false
	for _, arg := range args {
		found = found || arg == "-k"
	}
	if !found {
		t.Fatalf("kernel option missing: %q", args)
	}
}
