// Package cpu reads CPU, load, and CPU pressure observations from procfs.
package cpu

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

// Collector gathers one rootless CPU/load/PSI observation. ProcRoot is
// injectable for tests; an empty value means /proc.
type Collector struct{ ProcRoot string }

func (Collector) Name() string { return "cpu" }

func (c Collector) Collect(ctx context.Context) (collect.Data, error) {
	if err := ctx.Err(); err != nil {
		return collect.Data{}, err
	}
	root := c.ProcRoot
	if root == "" {
		root = "/proc"
	}
	snapshot, err := ReadSnapshot(root)
	if snapshot.At.IsZero() {
		return collect.Data{}, err
	}
	sampled := false
	data := collect.Data{Snapshot: snapshot, CPU: &model.CPU{Sampled: &sampled, Load1: snapshot.Load.One, Load5: snapshot.Load.Five, Load15: snapshot.Load.Fifteen, Runnable: int(snapshot.Stat.Runnable), Blocked: int(snapshot.Stat.Blocked)}}
	if snapshot.Pressure != nil {
		data.Pressure = &model.Pressure{CPU: toModelPressure(*snapshot.Pressure)}
	}
	return data, err
}

// Delta implements collect.DeltaCollector and converts the two private procfs
// snapshots into window-normalized CPU facts.
func (Collector) Delta(first, last collect.Data) (collect.Data, error) {
	start, ok := first.Snapshot.(Snapshot)
	if !ok {
		return finalGauges(last), errors.New("cpu: first snapshot has unexpected type")
	}
	end, ok := last.Snapshot.(Snapshot)
	if !ok {
		return finalGauges(last), errors.New("cpu: final snapshot has unexpected type")
	}
	if start.At.IsZero() || end.At.IsZero() {
		return finalGauges(last), errors.New("missing sample boundary")
	}
	delta, err := Between(start, end)
	if err != nil {
		return finalGauges(last), err
	}
	sampled := true
	data := collect.Data{CPU: &model.CPU{Sampled: &sampled, Utilization: delta.Utilization, User: delta.User, System: delta.System, IOWait: delta.IOWait, Steal: delta.Steal, Load1: delta.Load.One, Load5: delta.Load.Five, Load15: delta.Load.Fifteen, Runnable: int(delta.Runnable), Blocked: int(delta.Blocked)}}
	if delta.Pressure != nil {
		data.Pressure = &model.Pressure{CPU: toModelPressure(*delta.Pressure)}
	}
	return data, nil
}

// Trends exposes inexpensive CPU series collected during the common sampling
// window. The first utilization point is omitted because utilization requires
// a preceding counter snapshot.
func (Collector) Trends(samples []collect.Data) []model.Trend {
	utilization := make([]float64, 0, len(samples))
	load := make([]float64, 0, len(samples))
	pressure := make([]float64, 0, len(samples))
	var previous *Snapshot
	for _, sample := range samples {
		snapshot, ok := sample.Snapshot.(Snapshot)
		if !ok {
			continue
		}
		load = append(load, snapshot.Load.One)
		if snapshot.Pressure != nil {
			pressure = append(pressure, snapshot.Pressure.Some.Avg10)
		}
		if previous != nil {
			if delta, err := Between(*previous, snapshot); err == nil {
				utilization = append(utilization, delta.Utilization)
			}
		}
		previous = &snapshot
	}
	trends := []model.Trend{{Name: "cpu.load_1", Unit: "load", Values: load}, {Name: "cpu.psi_some_avg10", Unit: "percent", Values: pressure}}
	if len(utilization) > 0 {
		trends = append(trends, model.Trend{Name: "cpu.utilization", Unit: "fraction", Values: utilization})
	}
	return trends
}

func toModelPressure(p Pressure) model.PressureResource {
	out := model.PressureResource{SomeAvg10: p.Some.Avg10}
	if p.Full != nil {
		out.FullAvg10 = p.Full.Avg10
	}
	return out
}

// Times contains cumulative CPU scheduler time expressed in jiffies.
// The guest fields are intentionally retained but excluded from Total because
// they are already included in user and nice on Linux.
type Times struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal, Guest, GuestNice uint64
}

func (t Times) Total() uint64 {
	return t.User + t.Nice + t.System + t.Idle + t.IOWait + t.IRQ + t.SoftIRQ + t.Steal
}

// Stat is the useful subset of /proc/stat.
type Stat struct {
	Total           Times
	PerCPU          map[string]Times
	ContextSwitches uint64
	Interrupts      uint64
	SoftInterrupts  uint64
	Runnable        uint64
	Blocked         uint64
}

// Load is /proc/loadavg normalized into floats and task counts.
type Load struct {
	One, Five, Fifteen float64
	Running, Total     uint64
}

// PressureLine is one PSI line. A missing full line is represented by nil.
type PressureLine struct {
	Avg10, Avg60, Avg300 float64
	Total                uint64 // microseconds since boot
}

// Pressure represents CPU PSI. CPU pressure normally has only a "some" line.
type Pressure struct {
	Some PressureLine
	Full *PressureLine
}

// Snapshot is a point-in-time CPU observation. Counter rates and utilization
// are calculated by Delta so boot-long counters are not misreported.
type Snapshot struct {
	At       time.Time
	Stat     Stat
	Load     Load
	Pressure *Pressure
}

// Delta describes values accumulated during a sampling interval.
type Delta struct {
	Duration                    time.Duration
	Utilization                 float64 // 0..1
	User, System, IOWait, Steal float64 // 0..1 of elapsed CPU time
	ContextSwitches             uint64
	Interrupts                  uint64
	SoftInterrupts              uint64
	Runnable, Blocked           uint64 // final instantaneous values
	Load                        Load
	Pressure                    *Pressure
}

// ParseStat parses /proc/stat. Unknown fields are ignored for kernel
// compatibility, while malformed known fields return an error.
func ParseStat(r io.Reader) (Stat, error) {
	var out Stat
	out.PerCPU = make(map[string]Times)
	s := bufio.NewScanner(r)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "cpu":
			v, err := parseTimes(fields)
			if err != nil {
				return Stat{}, err
			}
			out.Total = v
		case "ctxt", "intr", "softirq", "procs_running", "procs_blocked":
			// intr and softirq append a variable number of per-source counters;
			// only their leading aggregate is needed here.
			if len(fields) < 2 || ((fields[0] == "ctxt" || fields[0] == "procs_running" || fields[0] == "procs_blocked") && len(fields) != 2) {
				return Stat{}, fmt.Errorf("proc stat %s: expected value", fields[0])
			}
			v, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return Stat{}, fmt.Errorf("proc stat %s: %w", fields[0], err)
			}
			switch fields[0] {
			case "ctxt":
				out.ContextSwitches = v
			case "intr":
				out.Interrupts = v
			case "softirq":
				out.SoftInterrupts = v
			case "procs_running":
				out.Runnable = v
			case "procs_blocked":
				out.Blocked = v
			}
		default:
			if strings.HasPrefix(fields[0], "cpu") {
				v, err := parseTimes(fields)
				if err != nil {
					return Stat{}, err
				}
				out.PerCPU[fields[0]] = v
			}
		}
	}
	if err := s.Err(); err != nil {
		return Stat{}, err
	}
	if out.Total.Total() == 0 {
		return Stat{}, errors.New("proc stat: missing cpu line")
	}
	return out, nil
}

func parseTimes(fields []string) (Times, error) {
	if len(fields) < 5 {
		return Times{}, fmt.Errorf("proc stat %s: too few CPU fields", fields[0])
	}
	var values [10]uint64
	for i := 1; i < len(fields) && i <= len(values); i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return Times{}, fmt.Errorf("proc stat %s: %w", fields[0], err)
		}
		values[i-1] = v
	}
	return Times{values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8], values[9]}, nil
}

func ParseLoad(r io.Reader) (Load, error) {
	fields, err := readFields(r)
	if err != nil {
		return Load{}, err
	}
	if len(fields) < 4 {
		return Load{}, errors.New("loadavg: too few fields")
	}
	parseFloat := func(v string) (float64, error) { return strconv.ParseFloat(v, 64) }
	one, err := parseFloat(fields[0])
	if err != nil {
		return Load{}, fmt.Errorf("loadavg 1m: %w", err)
	}
	five, err := parseFloat(fields[1])
	if err != nil {
		return Load{}, fmt.Errorf("loadavg 5m: %w", err)
	}
	fifteen, err := parseFloat(fields[2])
	if err != nil {
		return Load{}, fmt.Errorf("loadavg 15m: %w", err)
	}
	tasks := strings.Split(fields[3], "/")
	if len(tasks) != 2 {
		return Load{}, errors.New("loadavg: invalid task counts")
	}
	running, err := strconv.ParseUint(tasks[0], 10, 64)
	if err != nil {
		return Load{}, fmt.Errorf("loadavg running: %w", err)
	}
	total, err := strconv.ParseUint(tasks[1], 10, 64)
	if err != nil {
		return Load{}, fmt.Errorf("loadavg total: %w", err)
	}
	return Load{one, five, fifteen, running, total}, nil
}

func ParsePressure(r io.Reader) (Pressure, error) {
	var out Pressure
	var haveSome bool
	s := bufio.NewScanner(r)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) != 5 || (f[0] != "some" && f[0] != "full") {
			return Pressure{}, fmt.Errorf("pressure: invalid line %q", s.Text())
		}
		line, err := parsePressureFields(f[1:])
		if err != nil {
			return Pressure{}, err
		}
		if f[0] == "some" {
			out.Some = line
			haveSome = true
		} else {
			out.Full = &line
		}
	}
	if err := s.Err(); err != nil {
		return Pressure{}, err
	}
	if !haveSome {
		return Pressure{}, errors.New("pressure: missing some line")
	}
	return out, nil
}

func parsePressureFields(fields []string) (PressureLine, error) {
	var out PressureLine
	for _, field := range fields {
		p := strings.SplitN(field, "=", 2)
		if len(p) != 2 {
			return PressureLine{}, fmt.Errorf("pressure: invalid field %q", field)
		}
		switch p[0] {
		case "avg10":
			v, err := strconv.ParseFloat(p[1], 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				return PressureLine{}, errors.New("pressure: invalid avg10")
			}
			out.Avg10 = v
		case "avg60":
			v, err := strconv.ParseFloat(p[1], 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				if err == nil {
					err = errors.New("not finite")
				}
				return PressureLine{}, fmt.Errorf("pressure avg60: %w", err)
			}
			out.Avg60 = v
		case "avg300":
			v, err := strconv.ParseFloat(p[1], 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				if err == nil {
					err = errors.New("not finite")
				}
				return PressureLine{}, fmt.Errorf("pressure avg300: %w", err)
			}
			out.Avg300 = v
		case "total":
			v, err := strconv.ParseUint(p[1], 10, 64)
			if err != nil {
				return PressureLine{}, fmt.Errorf("pressure total: %w", err)
			}
			out.Total = v
		default:
			return PressureLine{}, fmt.Errorf("pressure: unknown field %q", p[0])
		}
	}
	return out, nil
}

// ReadSnapshot gathers procfs data. PSI is optional because it is absent on
// some kernels and in constrained containers.
func ReadSnapshot(procRoot string) (Snapshot, error) {
	statFile, err := os.Open(procRoot + "/stat")
	if err != nil {
		return Snapshot{}, fmt.Errorf("read cpu stat: %w", err)
	}
	defer statFile.Close()
	stat, err := ParseStat(statFile)
	if err != nil {
		return Snapshot{}, err
	}
	loadFile, err := os.Open(procRoot + "/loadavg")
	if err != nil {
		return Snapshot{}, fmt.Errorf("read loadavg: %w", err)
	}
	defer loadFile.Close()
	load, err := ParseLoad(loadFile)
	if err != nil {
		return Snapshot{}, err
	}
	out := Snapshot{At: time.Now(), Stat: stat, Load: load}
	psiFile, err := os.Open(procRoot + "/pressure/cpu")
	if err == nil {
		defer psiFile.Close()
		psi, parseErr := ParsePressure(psiFile)
		if parseErr != nil {
			return out, fmt.Errorf("parse cpu pressure: %w", parseErr)
		}
		out.Pressure = &psi
	}
	return out, nil
}

// Between derives deltas. A counter reset yields zero for that counter.
func Between(start, end Snapshot) (Delta, error) {
	if !end.At.After(start.At) {
		return Delta{}, errors.New("cpu sample timestamps are not increasing")
	}
	total := counterDelta(start.Stat.Total.Total(), end.Stat.Total.Total())
	if total == 0 {
		return Delta{}, errors.New("cpu CPU time did not advance")
	}
	d := Delta{Duration: end.At.Sub(start.At), ContextSwitches: counterDelta(start.Stat.ContextSwitches, end.Stat.ContextSwitches), Interrupts: counterDelta(start.Stat.Interrupts, end.Stat.Interrupts), SoftInterrupts: counterDelta(start.Stat.SoftInterrupts, end.Stat.SoftInterrupts), Runnable: end.Stat.Runnable, Blocked: end.Stat.Blocked, Load: end.Load, Pressure: end.Pressure}
	d.Utilization = 1 - ratio(counterDelta(start.Stat.Total.Idle, end.Stat.Total.Idle), total)
	d.User = ratio(counterDelta(start.Stat.Total.User, end.Stat.Total.User)+counterDelta(start.Stat.Total.Nice, end.Stat.Total.Nice), total)
	d.System = ratio(counterDelta(start.Stat.Total.System, end.Stat.Total.System)+counterDelta(start.Stat.Total.IRQ, end.Stat.Total.IRQ)+counterDelta(start.Stat.Total.SoftIRQ, end.Stat.Total.SoftIRQ), total)
	d.IOWait = ratio(counterDelta(start.Stat.Total.IOWait, end.Stat.Total.IOWait), total)
	d.Steal = ratio(counterDelta(start.Stat.Total.Steal, end.Stat.Total.Steal), total)
	return d, nil
}

func counterDelta(start, end uint64) uint64 {
	if end < start {
		return 0
	}
	return end - start
}
func ratio(n, d uint64) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}
func readFields(r io.Reader) ([]string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(b)), nil
}

func finalGauges(last collect.Data) collect.Data {
	if last.CPU == nil {
		return collect.Data{}
	}
	gauge := *last.CPU
	sampled := false
	gauge.Sampled = &sampled
	gauge.Utilization, gauge.User, gauge.System, gauge.IOWait, gauge.Steal = 0, 0, 0, 0, 0
	return collect.Data{CPU: &gauge, Pressure: last.Pressure}
}
