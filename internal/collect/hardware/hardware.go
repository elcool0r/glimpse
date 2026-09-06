// Package hardware reads optional EDAC controller error counters from sysfs.
package hardware

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

type Collector struct {
	SysRoot  string
	readDir  func(string) ([]os.DirEntry, error)
	readFile func(string) ([]byte, error)
}

func New() *Collector             { return &Collector{readDir: os.ReadDir, readFile: os.ReadFile} }
func (c *Collector) Name() string { return "hardware-errors" }

// Static marks EDAC counters as gauges: they are cumulative since boot and are
// reported as such, never as sampled deltas.
func (c *Collector) Static() {}

func (c *Collector) Collect(ctx context.Context) (collect.Data, error) {
	if err := ctx.Err(); err != nil {
		return collect.Data{}, err
	}
	root := c.SysRoot
	if root == "" {
		root = "/sys"
	}
	readDir, readFile := c.readDir, c.readFile
	if readDir == nil {
		readDir = os.ReadDir
	}
	if readFile == nil {
		readFile = os.ReadFile
	}
	edac := filepath.Join(root, "devices/system/edac/mc")
	entries, err := readDir(edac)
	if err != nil {
		return collect.Data{Diagnostics: []model.CollectionStatus{{Status: "unavailable", Detail: "EDAC counters: " + err.Error()}}}, nil
	}
	hardware := &model.HardwareErrors{Available: true}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return collect.Data{}, err
		}
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "mc") {
			continue
		}
		path := filepath.Join(edac, entry.Name())
		ce, ceOK := readCounter(readFile, filepath.Join(path, "ce_count"))
		ue, ueOK := readCounter(readFile, filepath.Join(path, "ue_count"))
		if !ceOK && !ueOK {
			continue
		}
		name := entry.Name()
		if raw, err := readFile(filepath.Join(path, "mc_name")); err == nil && strings.TrimSpace(string(raw)) != "" {
			name = strings.TrimSpace(string(raw))
		}
		hardware.Controllers = append(hardware.Controllers, model.HardwareErrorController{Name: name, CorrectableErrors: ce, UncorrectableErrors: ue})
	}
	sort.Slice(hardware.Controllers, func(i, j int) bool { return hardware.Controllers[i].Name < hardware.Controllers[j].Name })
	return collect.Data{Hardware: hardware}, nil
}

func readCounter(readFile func(string) ([]byte, error), path string) (uint64, bool) {
	raw, err := readFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	return v, err == nil
}
