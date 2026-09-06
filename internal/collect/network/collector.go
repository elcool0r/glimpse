package network

import (
	"context"
	"errors"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

// Snapshot is a point-in-time interface observation. The timestamp lives with
// the counters it belongs to, which is the same arrangement the CPU, memory
// and disk collectors use.
type Snapshot struct {
	At         time.Time
	Interfaces []Interface
}

// Collector captures cumulative interface counters and derives their sampled
// deltas through collect.DeltaCollector.
type Collector struct{ ProcRoot, SysRoot string }

func (Collector) Name() string { return "network" }

func (c Collector) Collect(ctx context.Context) (collect.Data, error) {
	interfaces, err := Collect(ctx, c.ProcRoot, c.SysRoot)
	if err != nil {
		return collect.Data{}, err
	}
	return collect.Data{Snapshot: Snapshot{At: time.Now(), Interfaces: interfaces}}, nil
}

func (Collector) Delta(first, last collect.Data) (collect.Data, error) {
	before, beforeOK := first.Snapshot.(Snapshot)
	after, afterOK := last.Snapshot.(Snapshot)
	if !afterOK {
		return collect.Data{}, errors.New("network: invalid final snapshot")
	}
	if !beforeOK {
		// The final observation is still a valid interface inventory. Report it
		// with zero counters and no sample interval rather than discarding it.
		return finalGauges(after), errors.New("network: invalid first snapshot")
	}
	previous := make(map[string]Counters, len(before.Interfaces))
	for _, iface := range before.Interfaces {
		previous[iface.Name] = iface.Counters
	}
	duration := sampleSeconds(before.At, after.At)
	metrics := make([]model.Network, 0, len(after.Interfaces))
	for _, iface := range after.Interfaces {
		// A newly created interface has no sampling baseline. Reporting its
		// lifetime counters as a delta would create a false network warning.
		// Omit it for this window and include it once a complete interval is
		// available.
		baseline, exists := previous[iface.Name]
		if !exists {
			continue
		}
		delta := Delta(baseline, iface.Counters)
		entry := linkFacts(iface)
		entry.SampleDurationSeconds = duration
		entry.RXBytes, entry.TXBytes = delta.RXBytes, delta.TXBytes
		entry.RXPackets, entry.TXPackets = delta.RXPackets, delta.TXPackets
		entry.RXErrors, entry.TXErrors = delta.RXErrors, delta.TXErrors
		entry.RXDropped, entry.TXDropped = delta.RXDrop, delta.TXDrop
		entry.RXFIFOErrors, entry.TXFIFOErrors = delta.RXFIFO, delta.TXFIFO
		entry.RXFrameErrors, entry.TXCarrierErrors = delta.RXFrame, delta.TXCarrier
		entry.Collisions = delta.Collisions
		metrics = append(metrics, entry)
	}
	return collect.Data{Network: metrics}, nil
}

// finalGauges keeps the interface inventory when no interval could be derived.
// Counters are zero and SampleDurationSeconds is absent, so neither analysis
// nor rendering can mistake them for observed activity.
func finalGauges(last Snapshot) collect.Data {
	metrics := make([]model.Network, 0, len(last.Interfaces))
	for _, iface := range last.Interfaces {
		metrics = append(metrics, linkFacts(iface))
	}
	return collect.Data{Network: metrics}
}

// linkFacts copies the sysfs gauges describing the link itself. They are
// current values rather than deltas, so they are equally valid with or without
// a sampling interval. Pointer values are copied so the reported metric does
// not alias the collector's snapshot.
func linkFacts(iface Interface) model.Network {
	entry := model.Network{Name: iface.Name, Operational: iface.OperState, MTU: iface.MTU, Duplex: iface.Duplex}
	if iface.Carrier != nil {
		carrier := *iface.Carrier
		entry.Carrier = &carrier
	}
	if iface.SpeedMbps != nil {
		speed := *iface.SpeedMbps
		entry.SpeedMbps = &speed
	}
	return entry
}

func sampleSeconds(first, last time.Time) float64 {
	if first.IsZero() || !last.After(first) {
		return 0
	}
	return last.Sub(first).Seconds()
}
