package collect_test

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/cpu"
	"github.com/elcool0r/glimpse/internal/collect/disk"
	"github.com/elcool0r/glimpse/internal/collect/memory"
	"github.com/elcool0r/glimpse/internal/collect/network"
	"github.com/elcool0r/glimpse/internal/collect/process"
)

// Every DeltaCollector must return the final observation's gauges alongside its
// error. Returning an empty Data erases metrics that were collected
// successfully: the application applies the delta result, so a baseline hiccup
// at one boundary used to remove the whole category from the report.
func TestDeltaImplementationsPreserveFinalObservation(t *testing.T) {
	cases := []struct {
		name    string
		sampler collect.DeltaCollector
		final   collect.Data
		check   func(collect.Data) bool
	}{
		{
			name:    "cpu",
			sampler: cpu.Collector{},
			final:   mustCollect(t, cpu.Collector{}),
			check:   func(d collect.Data) bool { return d.CPU != nil && d.CPU.Sampled != nil && !*d.CPU.Sampled },
		},
		{
			name:    "memory",
			sampler: memory.Collector{},
			final:   mustCollect(t, memory.Collector{}),
			check:   func(d collect.Data) bool { return d.Memory != nil && d.Memory.Sampled != nil && !*d.Memory.Sampled },
		},
		{
			name:    "disk",
			sampler: disk.Collector{},
			final:   mustCollect(t, disk.Collector{}),
			check: func(d collect.Data) bool {
				for _, disk := range d.Disks {
					if disk.Sampled == nil || *disk.Sampled {
						return false
					}
				}
				return d.Disks != nil
			},
		},
		{
			name:    "network",
			sampler: network.Collector{},
			final:   mustCollect(t, network.Collector{}),
			check: func(d collect.Data) bool {
				for _, iface := range d.Network {
					if iface.Sampled == nil || *iface.Sampled {
						return false
					}
				}
				return d.Network != nil
			},
		},
		{
			name:    "tcp",
			sampler: network.TCPCollector{},
			final:   mustCollect(t, network.TCPCollector{}),
			check:   func(d collect.Data) bool { return d.TCP != nil && d.TCP.Sampled != nil && !*d.TCP.Sampled },
		},
		{
			name:    "processes",
			sampler: process.Collector{},
			final:   mustCollect(t, process.Collector{}),
			check: func(d collect.Data) bool {
				return d.Processes != nil && d.Processes.CPUSampled != nil && !*d.Processes.CPUSampled
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.final.Snapshot == nil {
				t.Skipf("%s is not observable in this environment", tc.name)
			}
			// An absent baseline is the realistic failure: the first boundary
			// errored, or ran out of its budget.
			got, err := tc.sampler.Delta(collect.Data{}, tc.final)
			if err == nil {
				t.Fatalf("%s: expected an error without a baseline", tc.name)
			}
			if !tc.check(got) {
				t.Fatalf("%s: final gauges lost on delta failure: %+v", tc.name, got)
			}
		})
	}
}

func mustCollect(t *testing.T, c collect.Collector) collect.Data {
	t.Helper()
	data, err := c.Collect(t.Context())
	if err != nil {
		t.Logf("%s unavailable here: %v", c.Name(), err)
		return collect.Data{}
	}
	return data
}
