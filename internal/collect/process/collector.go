package process

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

const minimumDStateObservationInterval = 5 * time.Second

type Collector struct {
	ProcRoot string
	Limit    int
}

func (Collector) Name() string { return "processes" }

func (c Collector) Collect(ctx context.Context) (collect.Data, error) {
	snapshot, err := Collect(ctx, c.ProcRoot, c.Limit)
	if err != nil {
		return collect.Data{}, err
	}
	return collect.Data{Snapshot: snapshot}, nil
}

// Delta ranks CPU consumers by scheduler-time growth within the sample. The
// aggregate /proc/stat delta makes the resulting fraction comparable across
// machines: 1.0 means one fully busy core.
func (c Collector) Delta(first, last collect.Data) (collect.Data, error) {
	after, afterOK := last.Snapshot.(Snapshot)
	if !afterOK {
		return collect.Data{}, fmt.Errorf("processes: invalid final snapshot")
	}
	before, beforeOK := first.Snapshot.(Snapshot)
	if !beforeOK {
		// Counts, zombies and resident memory are all point-in-time facts and
		// stay valid without a baseline; only the CPU ranking needs one. The
		// report keeps them, marked as unsampled CPU.
		return finalGauges(after, c.limit()), fmt.Errorf("processes: invalid first snapshot")
	}
	type baseline struct {
		cpu   uint64
		start uint64
	}
	previous := make(map[int]baseline, len(before.all))
	for _, p := range before.all {
		previous[p.PID] = baseline{cpu: p.CPUTimeTicks, start: p.StartTimeTicks}
	}
	byCPU := append([]Process(nil), after.all...)
	cpuSampled := before.CPUTicksAvailable && after.CPUTicksAvailable && before.CPUCount > 0 && before.CPUCount == after.CPUCount && after.TotalCPUTicks > before.TotalCPUTicks
	var totalDelta uint64
	if cpuSampled {
		totalDelta = after.TotalCPUTicks - before.TotalCPUTicks
	}
	for i := range byCPU {
		base, exists := previous[byCPU[i].PID]
		if !exists || base.start != byCPU[i].StartTimeTicks {
			byCPU[i].CPUTimeTicks = 0 // new process or PID reuse
			continue
		}
		byCPU[i].CPUTimeTicks = counterDelta(base.cpu, byCPU[i].CPUTimeTicks)
		if cpuSampled {
			byCPU[i].CPUFraction = float64(byCPU[i].CPUTimeTicks) / float64(totalDelta) * float64(after.CPUCount)
			byCPU[i].CPUAvailable = true
		}
	}
	limit := c.limit()
	byCPU = top(byCPU, limit, func(p Process) uint64 { return p.CPUTimeTicks })
	samplePtr := &cpuSampled
	byPID := make(map[int]Process, len(byCPU))
	for _, p := range byCPU {
		byPID[p.PID] = p
	}
	rss := make([]Process, 0, len(after.TopRSS))
	for _, p := range after.TopRSS {
		if sampled, ok := byPID[p.PID]; ok && sampled.StartTimeTicks == p.StartTimeTicks {
			p.CPUFraction, p.CPUAvailable = sampled.CPUFraction, sampled.CPUAvailable
		}
		rss = append(rss, p)
	}
	names := commandNames(after.all)
	var endpointDState []model.Process
	if !before.At.IsZero() && !after.At.IsZero() && after.At.Sub(before.At) >= minimumDStateObservationInterval {
		endpointDState = endpointDStateProcesses(before.all, after.all, limit)
	}
	return collect.Data{Processes: &model.Processes{Total: after.Processes, Running: after.Running, Blocked: after.Blocked, Zombies: after.Zombies, StuckProcesses: endpointDState, ZombieProcesses: zombies(after.all, limit), TopCPU: processes(byCPU, names), TopRSS: processes(rss, names), CPUSampled: samplePtr}}, nil
}

func (c Collector) limit() int {
	if c.Limit <= 0 {
		return 10
	}
	return c.Limit
}

// finalGauges reports the final process snapshot without sampled CPU.
func finalGauges(last Snapshot, limit int) collect.Data {
	unsampled := false
	names := commandNames(last.all)
	strip := func(in []Process) []model.Process {
		out := processes(in, names)
		for i := range out {
			out[i].CPUFraction = 0
			available := false
			out[i].CPUSampled = &available
		}
		return out
	}
	return collect.Data{Processes: &model.Processes{
		Total: last.Processes, Running: last.Running, Blocked: last.Blocked, Zombies: last.Zombies,
		ZombieProcesses: zombies(last.all, limit), TopCPU: strip(last.TopCPU), TopRSS: strip(last.TopRSS),
		CPUSampled: &unsampled,
	}}
}

// commandNames indexes every observed process so a parent can be named even
// when it is not itself among the top consumers, which is the usual case.
func commandNames(all []Process) map[int]string {
	names := make(map[int]string, len(all))
	for _, p := range all {
		names[p.PID] = p.Name
	}
	return names
}

func counterDelta(before, after uint64) uint64 {
	if after < before {
		return 0
	}
	return after - before
}

func processes(in []Process, names map[int]string) []model.Process {
	out := make([]model.Process, 0, len(in))
	for _, p := range in {
		available := p.CPUAvailable
		out = append(out, model.Process{PID: p.PID, ParentPID: p.ParentPID, Command: p.Name, ParentCommand: names[p.ParentPID], CPUFraction: p.CPUFraction, CPUSampled: &available, RSSBytes: p.RSSBytes, State: string(p.State)})
	}
	return out
}

// endpointDStateProcesses reports matching process identities observed in D
// state at both sampling boundaries. It does not establish the process state
// between those observations.
func endpointDStateProcesses(before, after []Process, limit int) []model.Process {
	baseline := make(map[int]Process, len(before))
	for _, p := range before {
		if p.State == 'D' && !p.Own {
			baseline[p.PID] = p
		}
	}
	matches := make([]Process, 0)
	for _, p := range after {
		if p.State != 'D' || p.Own {
			continue
		}
		if prior, ok := baseline[p.PID]; ok && prior.StartTimeTicks == p.StartTimeTicks {
			matches = append(matches, p)
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].PID < matches[j].PID })
	if len(matches) > limit {
		matches = matches[:limit]
	}
	parentNames := commandNames(after)
	result := make([]model.Process, 0, len(matches))
	for _, process := range matches {
		result = append(result, model.Process{PID: process.PID, ParentPID: process.ParentPID, Command: process.Name, ParentCommand: parentNames[process.ParentPID], RSSBytes: process.RSSBytes, State: string(process.State)})
	}
	return result
}

func zombies(in []Process, limit int) []model.Process {
	zombieList := make([]Process, 0)
	for _, p := range in {
		if p.State == 'Z' && !p.Own {
			zombieList = append(zombieList, p)
		}
	}
	sort.Slice(zombieList, func(i, j int) bool { return zombieList[i].PID < zombieList[j].PID })
	if len(zombieList) > limit {
		zombieList = zombieList[:limit]
	}
	parentNames := commandNames(in)
	result := make([]model.Process, 0, len(zombieList))
	for _, process := range zombieList {
		result = append(result, model.Process{PID: process.PID, ParentPID: process.ParentPID, Command: process.Name, ParentCommand: parentNames[process.ParentPID], RSSBytes: process.RSSBytes, State: string(process.State)})
	}
	return result
}
