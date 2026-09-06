// Package memory reads memory, VM, and memory-pressure observations from procfs.
package memory

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

// Collector gathers one rootless memory/vmstat/PSI observation. ProcRoot is
// injectable for tests; an empty value means /proc.
type Collector struct{ ProcRoot string }

func (Collector) Name() string { return "memory" }

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
	availableFraction := float64(0)
	if snapshot.Info.Total > 0 {
		availableFraction = float64(snapshot.Info.Available) / float64(snapshot.Info.Total)
	}
	memory := &model.Memory{Sampled: &sampled, TotalBytes: snapshot.Info.Total, AvailableBytes: snapshot.Info.Available, SwapTotalBytes: snapshot.Info.SwapTotal, SwapFreeBytes: snapshot.Info.SwapFree, AvailableFraction: availableFraction}
	if raw, readErr := os.ReadFile(root + "/sys/vm/swappiness"); readErr == nil {
		if value, parseErr := parseSwappiness(string(raw)); parseErr == nil {
			memory.Swappiness = &value
		}
	}
	data := collect.Data{Snapshot: snapshot, Memory: memory}
	if snapshot.Pressure != nil {
		data.Pressure = &model.Pressure{Memory: toModelPressure(*snapshot.Pressure)}
	}
	return data, err
}

// Delta implements collect.DeltaCollector and normalizes the pswpin/pswpout
// page counters into bytes using the local kernel's page size.
func (Collector) Delta(first, last collect.Data) (collect.Data, error) {
	start, ok := first.Snapshot.(Snapshot)
	if !ok {
		return finalGauges(last), errors.New("memory: first snapshot has unexpected type")
	}
	end, ok := last.Snapshot.(Snapshot)
	if !ok {
		return finalGauges(last), errors.New("memory: final snapshot has unexpected type")
	}
	if start.At.IsZero() || end.At.IsZero() {
		return finalGauges(last), errors.New("missing sample boundary")
	}
	delta, err := Between(start, end)
	if err != nil {
		return finalGauges(last), err
	}
	availableFraction := float64(0)
	if delta.Info.Total > 0 {
		availableFraction = float64(delta.Info.Available) / float64(delta.Info.Total)
	}
	pageSize := uint64(os.Getpagesize())
	sampled := true
	memory := &model.Memory{Sampled: &sampled, TotalBytes: delta.Info.Total, AvailableBytes: delta.Info.Available, SwapTotalBytes: delta.Info.SwapTotal, SwapFreeBytes: delta.Info.SwapFree, SwapInBytes: saturatingMultiply(delta.SwapIn, pageSize), SwapOutBytes: saturatingMultiply(delta.SwapOut, pageSize), PageFaults: delta.PageFault, MajorFaults: delta.MajorFault, AvailableFraction: availableFraction}
	if last.Memory != nil {
		memory.Swappiness = last.Memory.Swappiness
	}
	data := collect.Data{Memory: memory}
	if delta.Pressure != nil {
		data.Pressure = &model.Pressure{Memory: toModelPressure(*delta.Pressure)}
	}
	return data, nil
}

func parseSwappiness(raw string) (uint64, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil || v > 200 {
		return 0, fmt.Errorf("swappiness: invalid value %q", strings.TrimSpace(raw))
	}
	return v, nil
}

// Trends returns bounded gauges that make short-term memory changes visible
// without interpreting normal cache reclamation as a health problem.
func (Collector) Trends(samples []collect.Data) []model.Trend {
	available := make([]float64, 0, len(samples))
	pressure := make([]float64, 0, len(samples))
	for _, sample := range samples {
		if sample.Memory != nil {
			available = append(available, sample.Memory.AvailableFraction)
		}
		if sample.Pressure != nil {
			pressure = append(pressure, sample.Pressure.Memory.SomeAvg10)
		}
	}
	return []model.Trend{
		{Name: "memory.available", Unit: "fraction", Values: available},
		{Name: "memory.psi_some_avg10", Unit: "percent", Values: pressure},
	}
}

func toModelPressure(p Pressure) model.PressureResource {
	out := model.PressureResource{SomeAvg10: p.Some.Avg10}
	if p.Full != nil {
		out.FullAvg10 = p.Full.Avg10
	}
	return out
}

// Info is normalized /proc/meminfo. All fields are bytes.
type Info struct {
	Total, Available, Free, Buffers, Cached, SReclaimable uint64
	SwapTotal, SwapFree                                   uint64
	Active, Inactive, Dirty, Writeback, Slab              uint64
	PageTables, CommitLimit, CommittedAS                  uint64
}

// Used returns a cache-aware estimate based on MemAvailable.
func (m Info) Used() uint64 {
	if m.Available > m.Total {
		return 0
	}
	return m.Total - m.Available
}
func (m Info) SwapUsed() uint64 {
	if m.SwapFree > m.SwapTotal {
		return 0
	}
	return m.SwapTotal - m.SwapFree
}

// VMStat contains cumulative VM counters from /proc/vmstat.
type VMStat struct {
	PageIn, PageOut, SwapIn, SwapOut, PageFault, MajorFault uint64
}

// PressureLine is one memory PSI line. total is microseconds since boot.
type PressureLine struct {
	Avg10, Avg60, Avg300 float64
	Total                uint64
}
type Pressure struct {
	Some PressureLine
	Full *PressureLine
}

// Snapshot captures point-in-time memory state and cumulative counters.
type Snapshot struct {
	At       time.Time
	Info     Info
	VM       VMStat
	Pressure *Pressure
}

// Delta holds sampling-window counter increases. Page counters are pages;
// callers can use the host page size if they need byte estimates.
type Delta struct {
	Duration                                                time.Duration
	PageIn, PageOut, SwapIn, SwapOut, PageFault, MajorFault uint64
	Info                                                    Info
	Pressure                                                *Pressure
}

func ParseMemInfo(r io.Reader) (Info, error) {
	var out Info
	s := bufio.NewScanner(r)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 2 {
			continue
		}
		key := strings.TrimSuffix(f[0], ":")
		if !consumedMemInfoKey(key) {
			// Rows this collector does not read cannot invalidate the ones it
			// does. Rejecting the whole file over an unrelated key would take
			// out the memory collector on the first kernel that adds a line in
			// a different unit.
			continue
		}
		value, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			return Info{}, fmt.Errorf("meminfo %s: %w", key, err)
		}
		// Linux meminfo is currently kB. Require the unit on the keys actually
		// used, to prevent silently accepting a format change as bytes.
		if len(f) >= 3 && f[2] != "kB" {
			return Info{}, fmt.Errorf("meminfo %s: unsupported unit %q", key, f[2])
		}
		if value > ^uint64(0)/1024 {
			return Info{}, fmt.Errorf("meminfo %s: overflows bytes", key)
		}
		value *= 1024
		switch key {
		case "MemTotal":
			out.Total = value
		case "MemAvailable":
			out.Available = value
		case "MemFree":
			out.Free = value
		case "Buffers":
			out.Buffers = value
		case "Cached":
			out.Cached = value
		case "SReclaimable":
			out.SReclaimable = value
		case "SwapTotal":
			out.SwapTotal = value
		case "SwapFree":
			out.SwapFree = value
		case "Active":
			out.Active = value
		case "Inactive":
			out.Inactive = value
		case "Dirty":
			out.Dirty = value
		case "Writeback":
			out.Writeback = value
		case "Slab":
			out.Slab = value
		case "PageTables":
			out.PageTables = value
		case "CommitLimit":
			out.CommitLimit = value
		case "Committed_AS":
			out.CommittedAS = value
		}
	}
	if err := s.Err(); err != nil {
		return Info{}, err
	}
	if out.Total == 0 {
		return Info{}, errors.New("meminfo: missing MemTotal")
	}
	return out, nil
}

// consumedMemInfoKey lists the keys ParseMemInfo stores. Keeping it beside the
// switch below makes the "unit must be kB" rule apply exactly to them.
func consumedMemInfoKey(key string) bool {
	switch key {
	case "MemTotal", "MemAvailable", "MemFree", "Buffers", "Cached", "SReclaimable",
		"SwapTotal", "SwapFree", "Active", "Inactive", "Dirty", "Writeback", "Slab",
		"PageTables", "CommitLimit", "Committed_AS":
		return true
	}
	return false
}

func ParseVMStat(r io.Reader) (VMStat, error) {
	var out VMStat
	s := bufio.NewScanner(r)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "pgpgin", "pgpgout", "pswpin", "pswpout", "pgfault", "pgmajfault":
			v, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				return VMStat{}, fmt.Errorf("vmstat %s: %w", f[0], err)
			}
			switch f[0] {
			case "pgpgin":
				out.PageIn = v
			case "pgpgout":
				out.PageOut = v
			case "pswpin":
				out.SwapIn = v
			case "pswpout":
				out.SwapOut = v
			case "pgfault":
				out.PageFault = v
			case "pgmajfault":
				out.MajorFault = v
			}
		}
	}
	return out, s.Err()
}

func ParsePressure(r io.Reader) (Pressure, error) {
	var out Pressure
	var haveSome bool
	s := bufio.NewScanner(r)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) != 5 || (f[0] != "some" && f[0] != "full") {
			return Pressure{}, fmt.Errorf("memory pressure: invalid line %q", s.Text())
		}
		line, err := parsePressureLine(f[1:])
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
		return Pressure{}, errors.New("memory pressure: missing some line")
	}
	return out, nil
}

func parsePressureLine(f []string) (PressureLine, error) {
	var out PressureLine
	for _, item := range f {
		p := strings.SplitN(item, "=", 2)
		if len(p) != 2 {
			return PressureLine{}, fmt.Errorf("memory pressure: malformed field %q", item)
		}
		switch p[0] {
		case "avg10":
			v, err := strconv.ParseFloat(p[1], 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				if err == nil {
					err = errors.New("not finite")
				}
				return PressureLine{}, err
			}
			out.Avg10 = v
		case "avg60":
			v, err := strconv.ParseFloat(p[1], 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				if err == nil {
					err = errors.New("not finite")
				}
				return PressureLine{}, err
			}
			out.Avg60 = v
		case "avg300":
			v, err := strconv.ParseFloat(p[1], 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				if err == nil {
					err = errors.New("not finite")
				}
				return PressureLine{}, err
			}
			out.Avg300 = v
		case "total":
			v, err := strconv.ParseUint(p[1], 10, 64)
			if err != nil {
				return PressureLine{}, err
			}
			out.Total = v
		default:
			return PressureLine{}, fmt.Errorf("memory pressure: unknown field %q", p[0])
		}
	}
	return out, nil
}

// ReadSnapshot uses procRoot (normally /proc); unavailable PSI is not fatal.
func ReadSnapshot(procRoot string) (Snapshot, error) {
	memFile, err := os.Open(procRoot + "/meminfo")
	if err != nil {
		return Snapshot{}, fmt.Errorf("read meminfo: %w", err)
	}
	defer memFile.Close()
	info, err := ParseMemInfo(memFile)
	if err != nil {
		return Snapshot{}, err
	}
	vmFile, err := os.Open(procRoot + "/vmstat")
	if err != nil {
		return Snapshot{}, fmt.Errorf("read vmstat: %w", err)
	}
	defer vmFile.Close()
	vm, err := ParseVMStat(vmFile)
	if err != nil {
		return Snapshot{}, err
	}
	out := Snapshot{At: time.Now(), Info: info, VM: vm}
	psiFile, err := os.Open(procRoot + "/pressure/memory")
	if err == nil {
		defer psiFile.Close()
		psi, parseErr := ParsePressure(psiFile)
		if parseErr != nil {
			return out, fmt.Errorf("parse memory pressure: %w", parseErr)
		}
		out.Pressure = &psi
	}
	return out, nil
}

func Between(start, end Snapshot) (Delta, error) {
	if !end.At.After(start.At) {
		return Delta{}, errors.New("memory sample timestamps are not increasing")
	}
	return Delta{Duration: end.At.Sub(start.At), PageIn: delta(start.VM.PageIn, end.VM.PageIn), PageOut: delta(start.VM.PageOut, end.VM.PageOut), SwapIn: delta(start.VM.SwapIn, end.VM.SwapIn), SwapOut: delta(start.VM.SwapOut, end.VM.SwapOut), PageFault: delta(start.VM.PageFault, end.VM.PageFault), MajorFault: delta(start.VM.MajorFault, end.VM.MajorFault), Info: end.Info, Pressure: end.Pressure}, nil
}

func delta(start, end uint64) uint64 {
	if end < start {
		return 0
	}
	return end - start
}

func saturatingMultiply(a, b uint64) uint64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > ^uint64(0)/b {
		return ^uint64(0)
	}
	return a * b
}

func finalGauges(last collect.Data) collect.Data {
	if last.Memory == nil {
		return collect.Data{}
	}
	gauge := *last.Memory
	sampled := false
	gauge.Sampled = &sampled
	gauge.SwapInBytes, gauge.SwapOutBytes, gauge.MajorFaults = 0, 0, 0
	return collect.Data{Memory: &gauge, Pressure: last.Pressure}
}
