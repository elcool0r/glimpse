package kernel

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/model"
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

func TestParseEventsRecognizesNewPatterns(t *testing.T) {
	input := `kernel: igb 0000:01:00.0 enp7s0: NIC Link is Down
kernel: igb 0000:01:00.0 enp7s0: NIC Link is Up 1000 Mbps Full Duplex
kernel: python3[12345]: segfault at 0 ip 00007f1234567890 sp 00007ffe12345678 error 4
kernel: NETDEV WATCHDOG: eth0 (r8169): transmit queue 0 timed out
kernel: EXT4-fs (sda1): re-mounting filesystem read-only
systemd[1]: Failed to write to /var/lib/foo: No space left on device`
	got := ParseEvents(input, time.Now())
	kinds := make([]string, len(got))
	for i, event := range got {
		kinds[i] = event.Kind
	}
	want := []string{"link_down", "link_up", "segfault", "netdev_watchdog", "filesystem_readonly_remount", "disk_full"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("got %#v, want %#v", kinds, want)
	}
}

// A virtual interface like a docker veth or a VM's tap device never actually
// emits the "NIC Link is Up/Down" driver message -- that phrasing comes
// specifically from physical Ethernet/Wi-Fi drivers -- but the filter is a
// deliberate backstop in case one ever does.
func TestFilterVirtualLinkEventsDropsSoftwareInterfaces(t *testing.T) {
	events := []model.LogEvent{
		{Kind: "link_down", Message: "enp7s0: NIC Link is Down"},
		{Kind: "link_down", Message: "veth3f2a91: NIC Link is Down"},
		{Kind: "link_up", Message: "docker0: NIC Link is Up"},
		{Kind: "oom", Message: "unrelated event, must pass through"},
	}
	got := filterVirtualLinkEvents(events)
	if len(got) != 2 {
		t.Fatalf("expected the two virtual-interface link events dropped, got %#v", got)
	}
	if got[0].Message != "enp7s0: NIC Link is Down" || got[1].Kind != "oom" {
		t.Fatalf("unexpected surviving events: %#v", got)
	}
}

// The prefix match must anchor to a word boundary, not any substring --
// otherwise a real interface whose name happens to contain "tap" or "wg" as
// a coincidental substring would be wrongly excluded.
func TestIsVirtualInterfaceMessageRequiresWordBoundary(t *testing.T) {
	if isVirtualInterfaceMessage("enp7s0: NIC Link is Down") {
		t.Fatal("a real interface name must not match")
	}
	if !isVirtualInterfaceMessage("veth1234: NIC Link is Down") {
		t.Fatal("a veth interface must match")
	}
	if !isVirtualInterfaceMessage("docker0: NIC Link is Up") {
		t.Fatal("docker0 must match")
	}
}

// The same incident kind spotted by two different scans (a plausible overlap
// once ENOSPC-style journal-wide grepping was added alongside the -k scans)
// must not be reported twice.
func TestAppendNewEventsDeduplicatesAcrossScans(t *testing.T) {
	seen := map[string]struct{}{}
	events := appendNewEvents(nil, seen, []model.LogEvent{{Kind: "disk_full", Message: "first"}})
	events = appendNewEvents(events, seen, []model.LogEvent{{Kind: "disk_full", Message: "second"}, {Kind: "segfault", Message: "third"}})
	if len(events) != 2 {
		t.Fatalf("expected the duplicate disk_full dropped, got %#v", events)
	}
	if events[0].Message != "first" || events[1].Kind != "segfault" {
		t.Fatalf("unexpected merge result: %#v", events)
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
	var calls [][]string
	c := New()
	c.lookPath = func(string) (string, error) { return "journalctl", nil }
	c.run = func(_ context.Context, _ string, got ...string) ([]byte, error) {
		calls = append(calls, got)
		return nil, nil
	}
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatalf("expected 3 journalctl invocations (priority scan, kernel grep scan, enospc grep scan), got %d: %#v", len(calls), calls)
	}
	for _, args := range calls {
		for _, arg := range args {
			if arg == "--kernel" {
				t.Fatalf("unsupported option used: %q", args)
			}
		}
	}
	// The first two scans read the kernel ring buffer; the third (ENOSPC)
	// deliberately does not, since applications log that, not the kernel.
	for i, args := range calls[:2] {
		found := false
		for _, arg := range args {
			found = found || arg == "-k"
		}
		if !found {
			t.Fatalf("call %d: kernel option missing: %q", i, args)
		}
	}
	for _, arg := range calls[2] {
		if arg == "-k" {
			t.Fatalf("the ENOSPC scan must not be kernel-ring-buffer-only: %q", calls[2])
		}
	}
}
