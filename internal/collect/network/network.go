// Package network collects interface counters and inexpensive sysfs link facts.
package network

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Counters struct {
	RXBytes, RXPackets, RXErrors, RXDrop uint64
	TXBytes, TXPackets, TXErrors, TXDrop uint64
	// /proc/net/dev already carries overrun, frame, collision and carrier
	// columns beside the ones above. They separate a physical link fault from
	// congestion, so the parser keeps them rather than discarding the fields it
	// has already split.
	RXFIFO, RXFrame, TXFIFO, TXCarrier, Collisions uint64
}
type Interface struct {
	Name string
	Counters
	OperState string
	Carrier   *bool
	MTU       uint64
	SpeedMbps *uint64
	Duplex    string
}

func ParseDev(r io.Reader) (map[string]Counters, error) {
	scanner := bufio.NewScanner(r)
	result := make(map[string]Counters)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue
		}
		parts := strings.SplitN(scanner.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		// One unreadable interface row is skipped; it must not remove every
		// interface from the report.
		if name == "" || len(fields) != 16 {
			continue
		}
		var values [16]uint64
		malformed := false
		for i, field := range fields {
			v, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				malformed = true
				break
			}
			values[i] = v
		}
		if malformed {
			continue
		}
		// Column order is the kernel's stable /proc/net/dev layout:
		// rx bytes packets errs drop fifo frame compressed multicast,
		// tx bytes packets errs drop fifo colls carrier compressed.
		result[name] = Counters{
			RXBytes: values[0], RXPackets: values[1], RXErrors: values[2], RXDrop: values[3],
			RXFIFO: values[4], RXFrame: values[5],
			TXBytes: values[8], TXPackets: values[9], TXErrors: values[10], TXDrop: values[11],
			TXFIFO: values[12], Collisions: values[13], TXCarrier: values[14],
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("/proc/net/dev: no readable interface counters")
	}
	return result, nil
}

// Delta returns counter growth. A reset conservatively produces zero rather than an underflow.
func Delta(before, after Counters) Counters {
	d := func(a, b uint64) uint64 {
		if b < a {
			return 0
		}
		return b - a
	}
	return Counters{
		RXBytes: d(before.RXBytes, after.RXBytes), RXPackets: d(before.RXPackets, after.RXPackets),
		RXErrors: d(before.RXErrors, after.RXErrors), RXDrop: d(before.RXDrop, after.RXDrop),
		TXBytes: d(before.TXBytes, after.TXBytes), TXPackets: d(before.TXPackets, after.TXPackets),
		TXErrors: d(before.TXErrors, after.TXErrors), TXDrop: d(before.TXDrop, after.TXDrop),
		RXFIFO: d(before.RXFIFO, after.RXFIFO), RXFrame: d(before.RXFrame, after.RXFrame),
		TXFIFO: d(before.TXFIFO, after.TXFIFO), TXCarrier: d(before.TXCarrier, after.TXCarrier),
		Collisions: d(before.Collisions, after.Collisions),
	}
}

func Collect(ctx context.Context, procRoot, sysRoot string) ([]Interface, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if sysRoot == "" {
		sysRoot = "/sys"
	}
	f, err := os.Open(filepath.Join(procRoot, "net/dev"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	counters, err := ParseDev(f)
	if err != nil {
		return nil, err
	}
	result := make([]Interface, 0, len(counters))
	for name, count := range counters {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		iface := Interface{Name: name, Counters: count}
		base := filepath.Join(sysRoot, "class/net", name)
		iface.OperState, _ = readString(filepath.Join(base, "operstate"))
		iface.Duplex, _ = readString(filepath.Join(base, "duplex"))
		iface.MTU, _ = readUint(filepath.Join(base, "mtu"))
		if v, err := readUint(filepath.Join(base, "carrier")); err == nil {
			b := v == 1
			iface.Carrier = &b
		}
		if v, err := readUint(filepath.Join(base, "speed")); err == nil {
			iface.SpeedMbps = &v
		}
		result = append(result, iface)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func readString(path string) (string, error) {
	b, err := os.ReadFile(path)
	return strings.TrimSpace(string(b)), err
}
func readUint(path string) (uint64, error) {
	s, err := readString(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(s, 10, 64)
}
