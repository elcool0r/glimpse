package process

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/collect"
)

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

// A process in D state at only one boundary is common and usually transient
// (a brief disk wait); it must not be reported as stuck.
func TestStuckInDRequiresBothBoundaries(t *testing.T) {
	before := []Process{{PID: 20, Name: "reader", State: 'D', StartTimeTicks: 5}}
	after := []Process{{PID: 20, Name: "reader", State: 'R', StartTimeTicks: 5}}
	if got := stuckInD(before, after, 10); len(got) != 0 {
		t.Fatalf("expected no stuck processes for a one-boundary D state, got %#v", got)
	}
}

func TestStuckInDReportsProcessBlockedAcrossTheWholeWindow(t *testing.T) {
	before := []Process{
		{PID: 1, Name: "supervisor"},
		{PID: 20, ParentPID: 1, Name: "reader", State: 'D', StartTimeTicks: 5},
	}
	after := []Process{
		{PID: 1, Name: "supervisor"},
		{PID: 20, ParentPID: 1, Name: "reader", State: 'D', StartTimeTicks: 5},
	}
	got := stuckInD(before, after, 10)
	if len(got) != 1 || got[0].PID != 20 || got[0].ParentPID != 1 || got[0].ParentCommand != "supervisor" || got[0].State != "D" {
		t.Fatalf("unexpected stuck processes: %#v", got)
	}
}

// A PID reused by an unrelated process must not be mistaken for the same
// process having stayed blocked.
func TestStuckInDRejectsPIDReuse(t *testing.T) {
	before := []Process{{PID: 20, Name: "reader", State: 'D', StartTimeTicks: 5}}
	after := []Process{{PID: 20, Name: "unrelated", State: 'D', StartTimeTicks: 99}}
	if got := stuckInD(before, after, 10); len(got) != 0 {
		t.Fatalf("expected reused PID to be rejected, got %#v", got)
	}
}
