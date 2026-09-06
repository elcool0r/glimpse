package storagehealth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/command"
	"github.com/elcool0r/glimpse/internal/model"
)

const (
	commandTimeout = 5 * time.Second
	// scanTimeout is the floor for the whole device sweep. The real budget
	// scales with the number of devices (see scanBudget): a fixed ten seconds
	// meant that on a multi-bay host the sweep stopped after two or three
	// disks and the rest were never examined, with only a verbose diagnostic
	// to say so.
	scanTimeout = 10 * time.Second
	maxScanTime = 20 * time.Second
	// scanParallelism bounds concurrent device commands. Devices are
	// independent and each carries its own timeout, so probing them serially
	// only multiplied the wall time.
	scanParallelism = 4
)

// scanBudget allows every device a turn: enough waves of parallel probes to
// cover them all, floored at scanTimeout and capped so one collector can never
// monopolize a collection boundary.
func scanBudget(devices int, perDevice time.Duration) time.Duration {
	waves := (devices + scanParallelism - 1) / scanParallelism
	budget := time.Duration(waves) * perDevice
	if budget < scanTimeout {
		budget = scanTimeout
	}
	if budget > maxScanTime {
		budget = maxScanTime
	}
	return budget
}

// Collector reads optional device health data. Commands are attempted only for
// physical block devices and failures (including insufficient privileges) are
// deliberately treated as unavailable coverage.
type Collector struct {
	SysRoot string
	Timeout time.Duration
	// MaxDuration bounds all optional device commands together. A zero value
	// uses scanTimeout, preventing many unavailable disks from extending a
	// short Glimpse sample by one per-device timeout.
	MaxDuration time.Duration
	lookPath    func(string) (string, error)
	run         func(context.Context, string, ...string) ([]byte, error)
}

func New() *Collector             { return &Collector{lookPath: exec.LookPath, run: runCommand} }
func (c *Collector) Name() string { return "device-health" }

// Static marks device health as a gauge. This matters most here: smartctl
// --xall reads the full SMART log and can spin up a parked drive, and none of
// the values it returns can change within one sampling window.
func (c *Collector) Static() {}

func (c *Collector) Collect(parent context.Context) (collect.Data, error) {
	devices, err := c.devices()
	if err != nil && !os.IsNotExist(err) && !os.IsPermission(err) {
		return collect.Data{}, err
	}
	if err != nil {
		return collect.Data{DeviceHealth: []model.DeviceHealth{}, Diagnostics: []model.CollectionStatus{{Collector: c.Name(), Status: "unavailable", Detail: err.Error()}}}, nil
	}
	if len(devices) == 0 {
		// Virtual-only hosts have no vendor SMART/NVMe device to query. Keep this
		// optional check silent instead of reporting missing utilities as a fault.
		return collect.Data{DeviceHealth: []model.DeviceHealth{}}, nil
	}
	lookup := c.lookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	smartctl, _ := lookup("smartctl")
	nvme, _ := lookup("nvme")
	if smartctl == "" && nvme == "" {
		return collect.Data{DeviceHealth: []model.DeviceHealth{}, Diagnostics: []model.CollectionStatus{{Collector: c.Name(), Status: "unavailable", Detail: "smartctl and nvme commands are unavailable"}}}, nil
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = commandTimeout
	}
	run := c.run
	if run == nil {
		run = runCommand
	}
	result := make([]model.DeviceHealth, 0, len(devices))
	diagnostics := make([]model.CollectionStatus, 0)
	maxDuration := c.MaxDuration
	if maxDuration <= 0 {
		maxDuration = scanBudget(len(devices), timeout)
	}
	scanCtx, scanCancel := context.WithTimeout(parent, maxDuration)
	defer scanCancel()

	outcomes := make([]probeResult, len(devices))
	var wg sync.WaitGroup
	gate := make(chan struct{}, scanParallelism)
	for i, device := range devices {
		wg.Add(1)
		go func(i int, device string) {
			defer wg.Done()
			gate <- struct{}{}
			defer func() { <-gate }()
			if scanCtx.Err() != nil {
				outcomes[i].skipped = true
				return
			}
			outcomes[i] = c.probe(scanCtx, run, smartctl, nvme, timeout, device)
		}(i, device)
	}
	wg.Wait()
	if parent.Err() != nil {
		return collect.Data{DeviceHealth: result, Diagnostics: diagnostics}, parent.Err()
	}
	skipped := make([]string, 0)
	for i, o := range outcomes {
		if o.skipped {
			skipped = append(skipped, devices[i])
			continue
		}
		if o.ok {
			result = append(result, o.device)
		}
		if o.diagnostic != nil {
			diagnostics = append(diagnostics, *o.diagnostic)
		}
	}
	if len(skipped) > 0 {
		diagnostics = append(diagnostics, model.CollectionStatus{Collector: c.Name(), Status: "unavailable",
			Detail: fmt.Sprintf("device scan deadline reached; %d of %d devices were not checked: %s", len(skipped), len(devices), strings.Join(skipped, ", "))})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Device < result[j].Device })
	return collect.Data{DeviceHealth: result, Diagnostics: diagnostics}, nil
}

// probeResult is one device outcome: the health facts, or the reason there
// are none, or a note that the sweep ran out of time before reaching it.
type probeResult struct {
	device     model.DeviceHealth
	ok         bool
	diagnostic *model.CollectionStatus
	skipped    bool
}

// probe reads one device's health. Every failure is coverage, not a finding.
func (c *Collector) probe(scanCtx context.Context, run func(context.Context, string, ...string) ([]byte, error), smartctl, nvme string, timeout time.Duration, device string) (result probeResult) {
	unavailable := func(detail string) {
		result.diagnostic = &model.CollectionStatus{Collector: c.Name(), Status: "unavailable", Detail: detail}
	}
	invalid := func(detail string) {
		result.diagnostic = &model.CollectionStatus{Collector: c.Name(), Status: "error", Detail: detail}
	}
	ctx, cancel := context.WithTimeout(scanCtx, timeout)
	defer cancel()

	if strings.HasPrefix(device, "nvme") && nvme != "" {
		raw, runErr := run(ctx, nvme, "smart-log", "--output-format=json", "/dev/"+device)
		if runErr != nil {
			unavailable(device + ": nvme smart-log failed: " + runErr.Error())
			return result
		}
		parsed, err := ParseNVMeJSON(device, raw)
		if err != nil {
			invalid(device + ": invalid nvme health output: " + err.Error())
			return result
		}
		result.device, result.ok = toModel(parsed), true
		return result
	}
	if smartctl == "" {
		unavailable(device + ": smartctl command unavailable")
		return result
	}
	raw, runErr := run(ctx, smartctl, "--json", "--xall", "/dev/"+device)
	if runErr != nil && !smartHealthExit(runErr) {
		unavailable(device + ": smartctl failed: " + runErr.Error())
		return result
	}
	parsed, err := ParseSmartJSON(device, raw)
	if err != nil {
		invalid(device + ": invalid SMART output: " + err.Error())
		return result
	}
	result.device, result.ok = toModel(parsed), true
	return result
}

func (c *Collector) devices() ([]string, error) {
	root := c.SysRoot
	if root == "" {
		root = "/sys"
	}
	entries, err := os.ReadDir(filepath.Join(root, "block"))
	if err != nil {
		return nil, err
	}
	devices := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		info, statErr := os.Stat(filepath.Join(root, "block", name))
		if statErr == nil && info.IsDir() && physicalDevice(name) {
			devices = append(devices, name)
		}
	}
	sort.Strings(devices)
	return devices, nil
}

func physicalDevice(name string) bool {
	return strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "hd") || strings.HasPrefix(name, "nvme")
}

func toModel(device Device) model.DeviceHealth {
	result := model.DeviceHealth{Device: device.Name, Kind: device.Kind, OverallPassed: device.OverallPassed,
		CriticalWarning: device.CriticalWarning, MediaErrors: device.MediaErrors, PendingSectors: device.PendingSectors,
		Uncorrectable: device.OfflineUncorrectable, ReallocatedSectors: device.ReallocatedSectors}
	if device.TemperatureC != nil {
		result.TemperatureC = *device.TemperatureC
	}
	if device.AvailableSpare != nil {
		result.AvailableSpare = *device.AvailableSpare / 100
	}
	if device.PercentageUsed != nil {
		result.PercentageUsed = *device.PercentageUsed / 100
	}
	if device.CRCErrors > 0 {
		result.Notes = append(result.Notes, fmt.Sprintf("CRC errors: %d", device.CRCErrors))
	}
	if device.UnsafeShutdowns > 0 {
		result.Notes = append(result.Notes, fmt.Sprintf("unsafe shutdowns: %d", device.UnsafeShutdowns))
	}
	return result
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return command.Output(ctx, name, args...)
}

// smartctl uses bits 3..7 for health findings, not command execution failure.
// Command/permission/parse failures (bits 0..2) remain unavailable coverage.
func smartHealthExit(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() > 0 && exit.ExitCode()&7 == 0
}
