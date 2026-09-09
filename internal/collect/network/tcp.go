package network

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

// ProtocolCounters retains the named kernel counters from /proc/net/snmp and
// /proc/net/netstat. Names are stable kernel ABI; unknown fields are retained
// so adding a relevant signal later requires no parser change.
type ProtocolCounters map[string]map[string]uint64

// SocketStats holds current socket gauges from /proc/net/sockstat.
type SocketStats map[string]map[string]uint64

type TCPSnapshot struct {
	At       time.Time
	SNMP     ProtocolCounters
	NetStat  ProtocolCounters
	SockStat SocketStats
	// Conntrack is nil when netfilter's connection tracker is not loaded,
	// which is the normal case on a host that does no filtering or NAT.
	Conntrack *ConntrackStats
}

// ConntrackStats holds netfilter counters summed across CPUs.
type ConntrackStats struct{ Drops, EarlyDrops, InsertFailed uint64 }

// ParseConntrackStats sums the per-CPU rows of /proc/net/stat/nf_conntrack.
// Columns are addressed by their header name rather than by position: kernels
// have added and removed columns over the years, and a name lookup means an
// absent counter contributes nothing instead of silently shifting every other
// value by one column.
func ParseConntrackStats(r io.Reader) (ConntrackStats, error) {
	s := bufio.NewScanner(r)
	if !s.Scan() {
		if err := s.Err(); err != nil {
			return ConntrackStats{}, err
		}
		return ConntrackStats{}, fmt.Errorf("nf_conntrack: no header")
	}
	index := make(map[string]int)
	for i, name := range strings.Fields(s.Text()) {
		index[name] = i
	}
	var out ConntrackStats
	targets := []struct {
		name string
		into *uint64
	}{{"drop", &out.Drops}, {"early_drop", &out.EarlyDrops}, {"insert_failed", &out.InsertFailed}}
	for line := 2; s.Scan(); line++ {
		fields := strings.Fields(s.Text())
		if len(fields) == 0 {
			continue
		}
		for _, target := range targets {
			i, ok := index[target.name]
			if !ok || i >= len(fields) {
				continue
			}
			// The kernel prints these counters in hex with no 0x prefix.
			value, err := strconv.ParseUint(fields[i], 16, 64)
			if err != nil {
				return ConntrackStats{}, fmt.Errorf("nf_conntrack %s line %d: %w", target.name, line, err)
			}
			*target.into += value
		}
	}
	if err := s.Err(); err != nil {
		return ConntrackStats{}, err
	}
	return out, nil
}

func readConntrackStatFile(path string) (ConntrackStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return ConntrackStats{}, err
	}
	defer f.Close()
	return ParseConntrackStats(f)
}

// ParseProtocolCounters parses alternating "Protocol: keys" and "Protocol:
// values" lines. It is shared by snmp and netstat, whose formats are alike.
func ParseProtocolCounters(r io.Reader) (ProtocolCounters, error) {
	s := bufio.NewScanner(r)
	out := make(ProtocolCounters)
	var pendingProtocol string
	var pendingKeys []string
	for line := 1; s.Scan(); line++ {
		text := strings.TrimSpace(s.Text())
		if text == "" {
			continue
		}
		parts := strings.SplitN(text, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			return nil, fmt.Errorf("protocol counters line %d: missing protocol prefix", line)
		}
		protocol := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if pendingProtocol == "" {
			if len(fields) == 0 {
				return nil, fmt.Errorf("protocol counters line %d: empty header", line)
			}
			pendingProtocol, pendingKeys = protocol, fields
			continue
		}
		if protocol != pendingProtocol {
			return nil, fmt.Errorf("protocol counters line %d: expected %s values, got %s", line, pendingProtocol, protocol)
		}
		if len(fields) != len(pendingKeys) {
			return nil, fmt.Errorf("protocol counters %s: %d values for %d keys", protocol, len(fields), len(pendingKeys))
		}
		values := make(map[string]uint64, len(pendingKeys))
		for i, raw := range fields {
			// Not every field is an unsigned counter: RFC 1213 defines
			// Tcp.MaxConn as signed, and Linux reports -1 for a dynamic
			// limit. Rejecting the file over it made every counter in it
			// unavailable on an ordinary host.
			value, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("protocol counters %s.%s: %w", protocol, pendingKeys[i], err)
			}
			if value < 0 {
				value = 0
			}
			values[pendingKeys[i]] = uint64(value)
		}
		out[protocol] = values
		pendingProtocol, pendingKeys = "", nil
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if pendingProtocol != "" {
		return nil, fmt.Errorf("protocol counters: missing values for %s", pendingProtocol)
	}
	return out, nil
}

// ParseSockStat parses the token-pair gauges reported per socket family.
func ParseSockStat(r io.Reader) (SocketStats, error) {
	s := bufio.NewScanner(r)
	out := make(SocketStats)
	for line := 1; s.Scan(); line++ {
		text := strings.TrimSpace(s.Text())
		if text == "" {
			continue
		}
		parts := strings.SplitN(text, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			return nil, fmt.Errorf("sockstat line %d: invalid record", line)
		}
		fields := strings.Fields(parts[1])
		if len(fields)%2 != 0 {
			return nil, fmt.Errorf("sockstat %s: key without value", parts[0])
		}
		values := make(map[string]uint64, len(fields)/2)
		for i := 0; i < len(fields); i += 2 {
			value, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("sockstat %s.%s: %w", parts[0], fields[i], err)
			}
			values[fields[i]] = value
		}
		out[strings.TrimSpace(parts[0])] = values
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func readProtocolFile(path string) (ProtocolCounters, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseProtocolCounters(f)
}

func readSockStatFile(path string) (SocketStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseSockStat(f)
}

// ReadTCPSnapshot collects optional TCP/IP capabilities independently. snmp
// is the useful baseline; unavailable netstat or sockstat merely reduces the
// fields available to analysis in restricted Linux environments.
func ReadTCPSnapshot(ctx context.Context, procRoot string) (TCPSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return TCPSnapshot{}, err
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	netRoot := filepath.Join(procRoot, "net")
	snmp, err := readProtocolFile(filepath.Join(netRoot, "snmp"))
	if err != nil {
		return TCPSnapshot{}, err
	}
	result := TCPSnapshot{At: time.Now(), SNMP: snmp}
	if stats, err := readProtocolFile(filepath.Join(netRoot, "netstat")); err == nil {
		result.NetStat = stats
	}
	if stats, err := readSockStatFile(filepath.Join(netRoot, "sockstat")); err == nil {
		result.SockStat = stats
	}
	if stats, err := readConntrackStatFile(filepath.Join(netRoot, "stat/nf_conntrack")); err == nil {
		result.Conntrack = &stats
	}
	return result, nil
}

func protocolValue(source ProtocolCounters, protocol, name string) uint64 {
	return source[protocol][name]
}
func socketValue(source SocketStats, protocol, name string) uint64 { return source[protocol][name] }
func counterDelta(before, after uint64) uint64 {
	if after < before {
		return 0
	}
	return after - before
}

// TCPCollector adds host-wide TCP/IP health inputs alongside interface facts.
// It intentionally does not use external commands and is rootless.
type TCPCollector struct{ ProcRoot string }

func (TCPCollector) Name() string { return "tcp" }

func (c TCPCollector) Collect(ctx context.Context) (collect.Data, error) {
	snapshot, err := ReadTCPSnapshot(ctx, c.ProcRoot)
	if err != nil {
		return collect.Data{}, err
	}
	return collect.Data{Snapshot: snapshot}, nil
}

func (TCPCollector) Delta(first, last collect.Data) (collect.Data, error) {
	after, afterOK := last.Snapshot.(TCPSnapshot)
	if !afterOK {
		return collect.Data{}, fmt.Errorf("tcp: invalid final snapshot")
	}
	before, beforeOK := first.Snapshot.(TCPSnapshot)
	if !beforeOK {
		// Socket gauges are current values and remain valid without a baseline.
		// Counter deltas stay zero so no retransmission or overflow rule fires.
		return tcpFinalGauges(after), fmt.Errorf("tcp: invalid first snapshot")
	}
	if before.At.IsZero() || after.At.IsZero() || !after.At.After(before.At) {
		return tcpFinalGauges(after), fmt.Errorf("tcp: invalid sampling interval")
	}
	delta := func(protocol, field string) uint64 {
		return counterDelta(protocolValue(before.SNMP, protocol, field), protocolValue(after.SNMP, protocol, field))
	}
	extended := func(field string) uint64 {
		return counterDelta(protocolValue(before.NetStat, "TcpExt", field), protocolValue(after.NetStat, "TcpExt", field))
	}
	sampled := true
	tcp := &model.TCP{Sampled: &sampled, SegmentsIn: delta("Tcp", "InSegs"), SegmentsOut: delta("Tcp", "OutSegs"), RetransmittedSegments: delta("Tcp", "RetransSegs"), ActiveOpens: delta("Tcp", "ActiveOpens"), PassiveOpens: delta("Tcp", "PassiveOpens"), AttemptFails: delta("Tcp", "AttemptFails"), EstablishmentResets: delta("Tcp", "EstabResets"), ListenOverflows: extended("ListenOverflows"), ListenDrops: extended("ListenDrops"), UDPInErrors: delta("Udp", "InErrors"), IPReassemblyFailures: delta("Ip", "ReasmFails"), IPFragmentationFailures: delta("Ip", "FragFails"), CurrentEstablished: protocolValue(after.SNMP, "Tcp", "CurrEstab"), TimeWaitSockets: socketValue(after.SockStat, "TCP", "tw"), OrphanSockets: socketValue(after.SockStat, "TCP", "orphan")}
	// Conntrack needs both boundaries: without a baseline the only honest
	// answer is that no interval was observed, not that nothing was dropped.
	var conntrack *model.Conntrack
	if before.Conntrack != nil && after.Conntrack != nil {
		conntrack = &model.Conntrack{
			Drops:        counterDelta(before.Conntrack.Drops, after.Conntrack.Drops),
			EarlyDrops:   counterDelta(before.Conntrack.EarlyDrops, after.Conntrack.EarlyDrops),
			InsertFailed: counterDelta(before.Conntrack.InsertFailed, after.Conntrack.InsertFailed),
		}
	}
	return collect.Data{TCP: tcp, Conntrack: conntrack}, nil
}

// tcpFinalGauges retains the current socket counts when no interval is available.
func tcpFinalGauges(last TCPSnapshot) collect.Data {
	sampled := false
	return collect.Data{TCP: &model.TCP{
		Sampled:            &sampled,
		CurrentEstablished: protocolValue(last.SNMP, "Tcp", "CurrEstab"),
		TimeWaitSockets:    socketValue(last.SockStat, "TCP", "tw"),
		OrphanSockets:      socketValue(last.SockStat, "TCP", "orphan"),
	}}
}
