package resources

import (
	"context"
	"os"
	"testing"
)

func TestParseFileNR(t *testing.T) {
	open, max, err := ParseFileNR("120 20 1000\n")
	if err != nil || open != 100 || max != 1000 {
		t.Fatalf("got %d %d %v", open, max, err)
	}
}

func TestParseLoadAvgProcesses(t *testing.T) {
	got, err := ParseLoadAvgProcesses("0.01 0.02 0.03 2/456 789")
	if err != nil || got != 456 {
		t.Fatalf("got %d %v", got, err)
	}
}

func TestParsePortRange(t *testing.T) {
	low, high, err := ParsePortRange("32768 60999\n")
	if err != nil || low != 32768 || high != 60999 {
		t.Fatalf("got %d %d %v", low, high, err)
	}
}

func TestParsePortRangeRejectsInvalid(t *testing.T) {
	if _, _, err := ParsePortRange("70000 1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectorReadsInotifyLimits(t *testing.T) {
	files := map[string][]byte{
		"/proc/sys/fs/inotify/max_user_watches":   []byte("1048576\n"),
		"/proc/sys/fs/inotify/max_user_instances": []byte("8192\n"),
	}
	c := New()
	c.readFile = func(path string) ([]byte, error) {
		if value, ok := files[path]; ok {
			return value, nil
		}
		return nil, errMissing{}
	}
	got, err := c.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.Resources.InotifyWatchesMax != 1048576 || got.Resources.InotifyInstancesMax != 8192 {
		t.Fatalf("got %#v", got.Resources)
	}
}

type errMissing struct{}

func (errMissing) Error() string { return "missing" }

// The task count from /proc/loadavg counts threads, so the collector reports
// threads-max alongside pid_max instead of leaving analysis to compare a thread
// count against a highest-PID value.
func TestCollectorReportsBothTaskCeilings(t *testing.T) {
	files := map[string]string{
		"/proc/loadavg":                "0.10 0.20 0.30 3/812 9999\n",
		"/proc/sys/kernel/pid_max":     "4194304\n",
		"/proc/sys/kernel/threads-max": "63000\n",
	}
	c := New()
	c.readFile = func(path string) ([]byte, error) {
		if value, ok := files[path]; ok {
			return []byte(value), nil
		}
		return nil, os.ErrNotExist
	}
	data, err := c.Collect(context.Background())
	if err != nil || data.Resources == nil {
		t.Fatalf("data=%+v err=%v", data, err)
	}
	if data.Resources.Processes != 812 {
		t.Fatalf("task count=%d", data.Resources.Processes)
	}
	if data.Resources.ProcessesMaximum != 4194304 || data.Resources.ThreadsMaximum != 63000 {
		t.Fatalf("ceilings=%+v", data.Resources)
	}
}
