// Package networkstate collects bounded local socket and route inventory.
package networkstate

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/command"
	"github.com/elcool0r/glimpse/internal/model"
)

const (
	commandTimeout = 2 * time.Second
	maxOutput      = 128 << 10
	maxSockets     = 128
	maxRoutes      = 64
)

type Collector struct {
	Timeout  time.Duration
	lookPath func(string) (string, error)
	run      func(context.Context, string, ...string) ([]byte, error)
	readFile func(string) ([]byte, error)
}

func New() *Collector {
	return &Collector{lookPath: exec.LookPath, run: runCommand, readFile: os.ReadFile}
}
func (c *Collector) Name() string { return "network-state" }

// Static marks the socket and route inventory as a gauge.
func (c *Collector) Static() {}

func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	lookup, run, readFile := c.lookPath, c.run, c.readFile
	if lookup == nil {
		lookup = exec.LookPath
	}
	if run == nil {
		run = runCommand
	}
	if readFile == nil {
		readFile = os.ReadFile
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = commandTimeout
	}
	state := &model.NetworkState{}
	var diagnostics []model.CollectionStatus

	// The resolver configuration is a plain file read, so it is collected
	// whether or not iproute2 is installed. A minimal container has no ss but
	// still has a resolver worth reporting.
	if raw, err := readFile(resolvConfPath); err == nil {
		dns := ParseResolvConf(string(raw))
		state.DNS, state.Available = &dns, true
	} else {
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "resolv.conf: " + err.Error()})
	}

	if path, err := lookup("ss"); err != nil {
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "ss: " + err.Error()})
	} else {
		if raw, err := runWithTimeout(parent, timeout, run, path, "-H", "-lntu"); err == nil {
			state.ListeningSockets = ParseListeningSockets(string(raw))
			state.Available = true
		} else if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		} else {
			diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "ss listeners: " + err.Error()})
		}
		if raw, err := runWithTimeout(parent, timeout, run, path, "-H", "-tan"); err == nil {
			state.ConnectionStates = ParseConnectionStates(string(raw))
			state.Available = true
		} else if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		} else {
			diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "ss connections: " + err.Error()})
		}
	}

	// The routing table is looked up independently: ip and ss ship in the same
	// package on most distributions but not on all of them, and a missing ss
	// must not cost the default-route check.
	if ip, err := lookup("ip"); err == nil {
		if raw, err := runWithTimeout(parent, timeout, run, ip, "-o", "route", "show"); err == nil {
			state.Routes = ParseRoutes(string(raw))
			state.RoutesAvailable = true
			state.Available = true
		} else if parent.Err() != nil {
			return collect.Data{}, parent.Err()
		} else {
			diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: "ip route: " + err.Error()})
		}
	}

	if !state.Available {
		return collect.Data{Diagnostics: diagnostics}, nil
	}
	return collect.Data{NetworkState: state, Diagnostics: diagnostics}, nil
}

func ParseListeningSockets(raw string) []model.ListeningSocket {
	seen := make(map[string]struct{})
	out := make([]model.ListeningSocket, 0)
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || len(out) >= maxSockets {
			continue
		}
		protocol := strings.ToLower(fields[0])
		if protocol != "tcp" && protocol != "udp" {
			continue
		}
		address, port, ok := splitEndpoint(fields[4])
		if !ok {
			continue
		}
		key := protocol + "\x00" + address + "\x00" + strconv.Itoa(int(port))
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, model.ListeningSocket{Protocol: protocol, Address: address, Port: port})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func ParseConnectionStates(raw string) []model.ConnectionState {
	counts := make(map[string]uint64)
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		state := fields[0] // `ss -H -tan` normally omits the tcp netid column.
		if strings.EqualFold(state, "tcp") {
			if len(fields) < 2 {
				continue
			}
			state = fields[1]
		}
		counts[strings.ToUpper(state)]++
	}
	out := make([]model.ConnectionState, 0, len(counts))
	for state, count := range counts {
		out = append(out, model.ConnectionState{State: state, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].State < out[j].State })
	return out
}

func ParseRoutes(raw string) []model.Route {
	out := make([]model.Route, 0)
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || len(out) >= maxRoutes {
			continue
		}
		route := model.Route{Destination: fields[0]}
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "via":
				route.Gateway = fields[i+1]
				i++
			case "dev":
				route.Device = fields[i+1]
				i++
			case "metric":
				if metric, err := strconv.ParseUint(fields[i+1], 10, 64); err == nil {
					route.Metric = &metric
				}
				i++
			}
		}
		out = append(out, route)
	}
	return out
}

func splitEndpoint(endpoint string) (string, uint16, bool) {
	endpoint = strings.TrimSpace(endpoint)
	index := strings.LastIndexByte(endpoint, ':')
	if index < 0 {
		return "", 0, false
	}
	port, err := strconv.ParseUint(endpoint[index+1:], 10, 16)
	if err != nil {
		return "", 0, false
	}
	address := strings.Trim(strings.TrimSpace(endpoint[:index]), "[]")
	return address, uint16(port), true
}

func runWithTimeout(parent context.Context, timeout time.Duration, run func(context.Context, string, ...string) ([]byte, error), path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return run(ctx, path, args...)
}

func runCommand(ctx context.Context, path string, args ...string) ([]byte, error) {
	// Output is truncated rather than abandoned: a partial socket inventory is
	// still a usable inventory, and the bound is only there to protect memory.
	result, err := command.Run(ctx, command.Options{MaxOutput: maxOutput}, path, args...)
	return result.Output, err
}
