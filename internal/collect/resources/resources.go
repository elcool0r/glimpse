// Package resources reads low-cost kernel capacity gauges. Missing files are
// expected in containers and kernels without optional subsystems.
package resources

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/cpu"
	"github.com/elcool0r/glimpse/internal/model"
)

type Collector struct {
	ProcRoot string
	readFile func(string) ([]byte, error)
}

func New() *Collector             { return &Collector{readFile: os.ReadFile} }
func (c *Collector) Name() string { return "resources" }

// Static marks kernel capacity values as gauges.
func (c *Collector) Static() {}

func (c *Collector) Collect(ctx context.Context) (collect.Data, error) {
	if err := ctx.Err(); err != nil {
		return collect.Data{}, err
	}
	proc := c.ProcRoot
	if proc == "" {
		proc = "/proc"
	}
	readFile := c.readFile
	if readFile == nil {
		readFile = os.ReadFile
	}
	result := &model.Resources{}
	if raw, err := readFile(proc + "/sys/fs/file-nr"); err == nil {
		open, maximum, parseErr := ParseFileNR(string(raw))
		if parseErr == nil {
			result.OpenFiles, result.OpenFilesMaximum = open, maximum
		}
	}
	if raw, err := readFile(proc + "/loadavg"); err == nil {
		processes, parseErr := ParseLoadAvgProcesses(string(raw))
		if parseErr == nil {
			result.Processes = processes
		}
	}
	if raw, err := readFile(proc + "/sys/kernel/pid_max"); err == nil {
		if value, parseErr := ParseUint(string(raw)); parseErr == nil {
			result.ProcessesMaximum = value
		}
	}
	// pid_max is the highest PID value, not a limit on how many tasks may
	// exist; threads-max is the ceiling the count from /proc/loadavg actually
	// approaches. Both are reported so the comparison is explicit.
	if raw, err := readFile(proc + "/sys/kernel/threads-max"); err == nil {
		if value, parseErr := ParseUint(string(raw)); parseErr == nil {
			result.ThreadsMaximum = value
		}
	}
	if raw, err := readFile(proc + "/sys/net/netfilter/nf_conntrack_count"); err == nil {
		if value, parseErr := ParseUint(string(raw)); parseErr == nil {
			result.Conntrack = value
		}
	}
	if raw, err := readFile(proc + "/sys/net/netfilter/nf_conntrack_max"); err == nil {
		if value, parseErr := ParseUint(string(raw)); parseErr == nil {
			result.ConntrackMaximum = value
		}
	}
	// Socket table ceilings. The kernel drops the oldest TIME_WAIT entries and
	// resets orphans once these are reached, so they are real limits rather
	// than advisory tuning values.
	for _, gauge := range []struct {
		path string
		into *uint64
	}{
		{"/sys/net/ipv4/tcp_max_tw_buckets", &result.TimeWaitMaximum},
		{"/sys/net/ipv4/tcp_max_orphans", &result.OrphanMaximum},
		{"/sys/net/core/somaxconn", &result.ListenBacklogMaximum},
	} {
		if raw, err := readFile(proc + gauge.path); err == nil {
			if value, parseErr := ParseUint(string(raw)); parseErr == nil {
				*gauge.into = value
			}
		}
	}
	if raw, err := readFile(proc + "/sys/net/ipv4/ip_local_port_range"); err == nil {
		low, high, parseErr := ParsePortRange(string(raw))
		if parseErr == nil {
			result.EphemeralPortLow, result.EphemeralPortHigh = low, high
		}
	}
	// The kernel does not expose a global inotify watch count, so no synthetic
	// usage is reported. Limits remain useful capacity facts in their own right.
	if raw, err := readFile(proc + "/sys/fs/inotify/max_user_watches"); err == nil {
		if value, parseErr := ParseUint(string(raw)); parseErr == nil {
			result.InotifyWatchesMax = value
		}
	}
	if raw, err := readFile(proc + "/sys/fs/inotify/max_user_instances"); err == nil {
		if value, parseErr := ParseUint(string(raw)); parseErr == nil {
			result.InotifyInstancesMax = value
		}
	}
	if *result == (model.Resources{}) {
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "no accessible kernel resource gauges"}}}, nil
	}
	return collect.Data{Resources: result}, nil
}

func ParseFileNR(raw string) (open, maximum uint64, err error) {
	fields := strings.Fields(raw)
	if len(fields) < 3 {
		return 0, 0, fmt.Errorf("file-nr: expected three fields")
	}
	allocated, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("file-nr allocated: %w", err)
	}
	unused, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("file-nr unused: %w", err)
	}
	maximum, err = strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("file-nr maximum: %w", err)
	}
	if unused > allocated {
		return 0, 0, fmt.Errorf("file-nr unused exceeds allocated")
	}
	return allocated - unused, maximum, nil
}

// ParseLoadAvgProcesses returns the total task count from /proc/loadavg. The
// kernel counts threads here, which is why it is compared against threads-max
// rather than pid_max.
func ParseLoadAvgProcesses(raw string) (uint64, error) {
	load, err := cpu.ParseLoad(strings.NewReader(raw))
	if err != nil {
		return 0, err
	}
	return load.Total, nil
}

func ParsePortRange(raw string) (uint64, uint64, error) {
	fields := strings.Fields(raw)
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("port range: expected two fields")
	}
	low, err := ParseUint(fields[0])
	if err != nil {
		return 0, 0, err
	}
	high, err := ParseUint(fields[1])
	if err != nil {
		return 0, 0, err
	}
	if low > high || high > 65535 {
		return 0, 0, fmt.Errorf("port range: invalid bounds")
	}
	return low, high, nil
}

func ParseUint(raw string) (uint64, error) { return strconv.ParseUint(strings.TrimSpace(raw), 10, 64) }
