package process

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
)

func TestCollectStampsSuccessfulSnapshot(t *testing.T) {
	procRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(procRoot, "stat"), []byte("cpu 1 2 3 4 5 6 7 8\ncpu0 1 2 3 4 5 6 7 8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	snapshot, err := Collect(context.Background(), procRoot, 10)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.At.Before(started) || snapshot.At.After(time.Now()) {
		t.Fatalf("snapshot timestamp %s is outside collection interval", snapshot.At)
	}
}

func TestParseStatWithParentheses(t *testing.T) {
	// Fields after ')' begin with state, then ppid. utime/stime are indexes 11/12, threads 17, rss 21.
	line := "123 (worker (main)) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25"
	p, err := ParseStat(line, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if p.PID != 123 || p.ParentPID != 1 || p.Name != "worker (main)" || p.State != 'R' || p.CPUTimeTicks != 23 || p.Threads != 17 || p.RSSBytes != 21*4096 || p.StartTimeTicks != 19 {
		t.Fatalf("wrong process: %#v", p)
	}
}

func TestParseCPUTicksExcludesGuestTime(t *testing.T) {
	got, err := ParseCPUTicks("cpu 10 20 30 40 50 60 70 80 900 1000\ncpu0 1 2 3 4 5 6 7 8\n")
	if err != nil || got != 360 {
		t.Fatalf("ticks=%d err=%v", got, err)
	}
}

func TestDeltaCalculatesCPUFractionAndRejectsPIDReuse(t *testing.T) {
	first := Snapshot{Processes: 2, TotalCPUTicks: 100, CPUCount: 2, CPUTicksAvailable: true, all: []Process{
		{PID: 10, Name: "old", CPUTimeTicks: 10, StartTimeTicks: 1},
		{PID: 11, Name: "same", CPUTimeTicks: 20, StartTimeTicks: 2},
	}}
	last := Snapshot{Processes: 2, TotalCPUTicks: 200, CPUCount: 2, CPUTicksAvailable: true, TopRSS: []Process{{PID: 11, Name: "same", RSSBytes: 99, StartTimeTicks: 2}}, all: []Process{
		{PID: 10, Name: "new", CPUTimeTicks: 90, StartTimeTicks: 9},
		{PID: 11, Name: "same", CPUTimeTicks: 40, StartTimeTicks: 2},
	}}
	c := Collector{Limit: 10}
	data, err := c.Delta(collect.Data{Snapshot: first}, collect.Data{Snapshot: last})
	if err != nil {
		t.Fatal(err)
	}
	if data.Processes == nil || data.Processes.CPUSampled == nil || !*data.Processes.CPUSampled {
		t.Fatalf("process sample metadata=%+v", data.Processes)
	}
	if len(data.Processes.TopCPU) != 2 || data.Processes.TopCPU[0].PID != 11 || data.Processes.TopCPU[0].CPUFraction <= 0 {
		t.Fatalf("top cpu=%+v", data.Processes.TopCPU)
	}
	for _, p := range data.Processes.TopCPU {
		if p.PID == 10 && p.CPUFraction != 0 {
			t.Fatalf("reused PID received old CPU sample: %+v", p)
		}
	}
	if len(data.Processes.TopRSS) != 1 || data.Processes.TopRSS[0].PID != 11 || data.Processes.TopRSS[0].CPUSampled == nil || !*data.Processes.TopRSS[0].CPUSampled {
		t.Fatalf("top rss CPU metadata missing: %+v", data.Processes.TopRSS)
	}
}

func TestDeltaMarksCPUSampleUnavailable(t *testing.T) {
	data, err := (Collector{}).Delta(collect.Data{Snapshot: Snapshot{TotalCPUTicks: 10}}, collect.Data{Snapshot: Snapshot{TotalCPUTicks: 10}})
	if err != nil || data.Processes == nil || data.Processes.CPUSampled == nil || *data.Processes.CPUSampled {
		t.Fatalf("data=%+v err=%v", data, err)
	}
}

func TestZombiesIncludeParentIdentity(t *testing.T) {
	got := zombies([]Process{{PID: 10, Name: "supervisor"}, {PID: 11, ParentPID: 10, Name: "worker", State: 'Z'}}, 10)
	if len(got) != 1 || got[0].PID != 11 || got[0].ParentPID != 10 || got[0].ParentCommand != "supervisor" {
		t.Fatalf("unexpected zombies: %#v", got)
	}
}

func TestEndpointDStateRequiresBothBoundaries(t *testing.T) {
	before := []Process{{PID: 20, Name: "reader", State: 'D', StartTimeTicks: 5}}
	after := []Process{{PID: 20, Name: "reader", State: 'R', StartTimeTicks: 5}}
	if got := endpointDStateProcesses(before, after, 10); len(got) != 0 {
		t.Fatalf("expected no match for a one-boundary D state, got %#v", got)
	}
}

func TestEndpointDStateReportsMatchingIdentityAtBothBoundaries(t *testing.T) {
	before := []Process{
		{PID: 1, Name: "supervisor"},
		{PID: 20, ParentPID: 1, Name: "reader", State: 'D', StartTimeTicks: 5},
	}
	after := []Process{
		{PID: 1, Name: "supervisor"},
		{PID: 20, ParentPID: 1, Name: "reader", State: 'D', StartTimeTicks: 5},
	}
	got := endpointDStateProcesses(before, after, 10)
	if len(got) != 1 || got[0].PID != 20 || got[0].ParentPID != 1 || got[0].ParentCommand != "supervisor" || got[0].State != "D" {
		t.Fatalf("unexpected endpoint matches: %#v", got)
	}
}

func TestEndpointDStateRejectsPIDReuse(t *testing.T) {
	before := []Process{{PID: 20, Name: "reader", State: 'D', StartTimeTicks: 5}}
	after := []Process{{PID: 20, Name: "unrelated", State: 'D', StartTimeTicks: 99}}
	if got := endpointDStateProcesses(before, after, 10); len(got) != 0 {
		t.Fatalf("expected reused PID to be rejected, got %#v", got)
	}
}

func TestDeltaRequiresMinimumDStateObservationInterval(t *testing.T) {
	start := time.Unix(100, 0)
	processes := []Process{{PID: 20, Name: "reader", State: 'D', StartTimeTicks: 5}}
	tests := []struct {
		name  string
		start time.Time
		end   time.Time
		want  int
	}{
		{name: "unset timestamps", want: 0},
		{name: "zero interval", start: start, end: start, want: 0},
		{name: "reversed timestamps", start: start, end: start.Add(-minimumDStateObservationInterval), want: 0},
		{name: "just below minimum", start: start, end: start.Add(minimumDStateObservationInterval - time.Nanosecond), want: 0},
		{name: "at minimum", start: start, end: start.Add(minimumDStateObservationInterval), want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := Snapshot{At: tt.start, all: processes}
			last := Snapshot{At: tt.end, all: processes}
			data, err := (Collector{}).Delta(collect.Data{Snapshot: first}, collect.Data{Snapshot: last})
			if err != nil {
				t.Fatal(err)
			}
			if got := len(data.Processes.StuckProcesses); got != tt.want {
				t.Fatalf("endpoint matches=%d, want %d", got, tt.want)
			}
		})
	}
}
