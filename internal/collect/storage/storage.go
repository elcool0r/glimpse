// Package storage collects optional Linux software storage-layer state.
package storage

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/collect/command"
	"github.com/elcool0r/glimpse/internal/collect/mountinfo"
	"github.com/elcool0r/glimpse/internal/model"
)

type Collector struct {
	ProcRoot, EtcRoot string
	Timeout           time.Duration
	lookPath          func(string) (string, error)
	run               func(context.Context, string, ...string) ([]byte, error)
}

func New() *Collector            { return &Collector{lookPath: exec.LookPath, run: runCommand} }
func (c Collector) Name() string { return "storage" }

// Static marks software storage-layer state as a gauge.
func (c Collector) Static() {}
func (c Collector) Collect(ctx context.Context) (collect.Data, error) {
	if err := ctx.Err(); err != nil {
		return collect.Data{}, err
	}
	proc := c.ProcRoot
	if proc == "" {
		proc = "/proc"
	}
	etc := c.EtcRoot
	if etc == "" {
		etc = "/etc"
	}
	d := collect.Data{}
	var diagnostics []model.CollectionStatus
	diagnose := func(detail string) {
		diagnostics = append(diagnostics, model.CollectionStatus{Status: "unavailable", Detail: detail})
	}

	if raw, err := os.ReadFile(filepath.Join(proc, "mdstat")); err == nil {
		d.SoftwareRAID = ParseMDStat(string(raw))
	} else if !os.IsNotExist(err) {
		// Absent mdstat means no md subsystem, which is not a gap. Anything
		// else is a check that could not run and must be reported as such.
		diagnose("software RAID: " + err.Error())
	}

	lookup := c.lookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	run := c.run
	if run == nil {
		run = runCommand
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	// LVM reporting tools need privileges on most distributions. A failure here
	// is missing coverage, never a healthy result: reporting nothing silently
	// would let an unprivileged run look like a host with no LVM problems.
	lvm := func(tool string, fields string, apply func(string)) {
		path, err := lookup(tool)
		if err != nil {
			diagnose(tool + ": " + err.Error())
			return
		}
		// Byte units remove the display formatting entirely. LVM otherwise
		// prints approximated sizes such as "<3.64t", which no numeric parser
		// can read and which silently became zero.
		raw, err := runWith(ctx, timeout, run, path, "--noheadings", "--separator", "|", "--units", "b", "--nosuffix", "-o", fields)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			diagnose(tool + ": " + err.Error())
			return
		}
		if d.LVM == nil {
			d.LVM = &model.LVM{}
		}
		apply(string(raw))
	}
	lvm("pvs", "pv_name,vg_name,pv_attr,pv_size,pv_free", func(raw string) { d.LVM.PhysicalVolumes = ParsePVs(raw) })
	lvm("vgs", "vg_name,vg_attr,vg_size,vg_free", func(raw string) { d.LVM.VolumeGroups = ParseVGs(raw) })
	lvm("lvs", "lv_name,vg_name,lv_attr,lv_size", func(raw string) { d.LVM.LogicalVolumes = ParseLVs(raw) })

	if raw, err := os.ReadFile(filepath.Join(etc, "fstab")); err == nil {
		d.MountChecks = ParseFstab(string(raw))
		if mountFile, mountErr := os.Open(filepath.Join(proc, "self/mountinfo")); mountErr == nil {
			entries, parseErr := mountinfo.Parse(mountFile)
			mountFile.Close()
			if parseErr == nil {
				active := mountinfo.Targets(entries)
				for i := range d.MountChecks {
					d.MountChecks[i].Active = active[d.MountChecks[i].MountPoint]
					d.MountChecks[i].ActiveKnown = true
				}
			} else {
				diagnose("mount table: " + parseErr.Error())
			}
		} else {
			diagnose("mount table: " + mountErr.Error())
		}
	} else if !os.IsNotExist(err) {
		diagnose("fstab: " + err.Error())
	}
	d.Diagnostics = diagnostics
	return d, nil
}

func runWith(parent context.Context, timeout time.Duration, run func(context.Context, string, ...string) ([]byte, error), name string, args ...string) ([]byte, error) {
	ctx, c := context.WithTimeout(parent, timeout)
	defer c()
	return run(ctx, name, args...)
}
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return command.Output(ctx, name, args...)
}

func ParseMDStat(text string) []model.SoftwareRAID {
	var out []model.SoftwareRAID
	var cur *model.SoftwareRAID
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && strings.HasPrefix(f[0], "md") && strings.Contains(line, ":") {
			if cur != nil {
				out = append(out, *cur)
			}
			level := ""
			for _, token := range f[3:] {
				if strings.HasPrefix(token, "raid") {
					level = strings.TrimPrefix(token, "raid")
					break
				}
			}
			cur = &model.SoftwareRAID{Device: "/dev/" + f[0], State: f[2], Level: level}
			continue
		}
		if cur == nil {
			continue
		}
		if strings.Contains(line, "[") && (strings.Contains(line, "resync") || strings.Contains(line, "recovery") || strings.Contains(line, "reshape") || strings.Contains(line, "rebuild")) {
			cur.ResyncProgress = strings.TrimSpace(line)
		}
		// State comes from the header row only. Matching "active" as a
		// substring of continuation text also matches "inactive", and only
		// worked because a second check happened to run afterwards.
		if start, end := strings.LastIndexByte(line, '['), strings.LastIndexByte(line, ']'); start >= 0 && end > start {
			members := line[start+1 : end]
			if strings.ContainsAny(members, "_F") {
				cur.State = "degraded"
			}
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

func parseRows(text string, n int) [][]string {
	var rows [][]string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := strings.Split(strings.TrimSpace(sc.Text()), "|")
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		if len(f) >= n {
			rows = append(rows, f)
		}
	}
	return rows
}

// LVM attribute strings are positional bit fields, not a set of flags, and
// their case is significant. Reading them as a character set marks healthy
// snapshot, origin and pvmove volumes as broken, and folds LVM's uppercase
// "invalid" markers onto their healthy lowercase counterparts.
//
// Layout used here (lvs(8), vgs(8)):
//
//	lv_attr[4] volume state: s/S suspended, I/S invalid snapshot, m/M mapped
//	           failure, X unknown
//	lv_attr[8] volume health: p partial, r refresh needed, m mismatches,
//	           X unknown
//	vg_attr[0] permissions: r read-only
//	vg_attr[3] partial: p
func lvAttrProblem(attr string) (bool, string) {
	if len(attr) < 10 {
		return false, ""
	}
	switch attr[4] {
	case 's', 'S':
		return true, "suspended"
	case 'I':
		return true, "invalid snapshot"
	case 'm', 'M':
		return true, "mapped failure"
	case 'X':
		return true, "unknown state"
	}
	switch attr[8] {
	case 'p':
		return true, "partial"
	case 'r':
		return true, "refresh needed"
	case 'm':
		return true, "mismatches recorded"
	case 'X':
		return true, "unknown health"
	}
	return false, ""
}

func vgAttrProblem(attr string) (bool, string) {
	if len(attr) < 6 {
		return false, ""
	}
	if attr[3] == 'p' {
		return true, "partial"
	}
	if attr[0] == 'r' {
		return true, "read-only"
	}
	return false, ""
}

func ParsePVs(s string) []model.LVMPhysicalVolume {
	var out []model.LVMPhysicalVolume
	for _, f := range parseRows(s, 5) {
		out = append(out, model.LVMPhysicalVolume{Name: f[0], Group: f[1], Attr: f[2], SizeBytes: parseSize(f[3]), FreeBytes: parseSize(f[4])})
	}
	return out
}
func ParseVGs(s string) []model.LVMVolumeGroup {
	var out []model.LVMVolumeGroup
	for _, f := range parseRows(s, 4) {
		vg := model.LVMVolumeGroup{Name: f[0], Attr: f[1], SizeBytes: parseSize(f[2]), FreeBytes: parseSize(f[3])}
		vg.NeedsReview, vg.ReviewReason = vgAttrProblem(vg.Attr)
		out = append(out, vg)
	}
	return out
}
func ParseLVs(s string) []model.LVMLogicalVolume {
	var out []model.LVMLogicalVolume
	for _, f := range parseRows(s, 4) {
		lv := model.LVMLogicalVolume{Name: f[0], Group: f[1], Attr: f[2], SizeBytes: parseSize(f[3])}
		lv.NeedsReview, lv.ReviewReason = lvAttrProblem(lv.Attr)
		out = append(out, lv)
	}
	return out
}

// parseSize reads an LVM size. Values are requested in bytes, but the display
// forms are still accepted so output from an older lvm2 remains readable: a
// leading "<" or ">" marks an approximated value, and a trailing unit letter
// scales it.
func parseSize(s string) uint64 {
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "<>~")
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mult := uint64(1)
	switch s[len(s)-1] {
	case 'b', 'B':
		s = s[:len(s)-1]
	case 'k', 'K':
		mult, s = 1<<10, s[:len(s)-1]
	case 'm', 'M':
		mult, s = 1<<20, s[:len(s)-1]
	case 'g', 'G':
		mult, s = 1<<30, s[:len(s)-1]
	case 't', 'T':
		mult, s = 1<<40, s[:len(s)-1]
	case 'p', 'P':
		mult, s = 1<<50, s[:len(s)-1]
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v < 0 {
		return 0
	}
	return uint64(v * float64(mult))
}

func ParseFstab(text string) []model.MountCheck {
	var out []model.MountCheck
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		// Swap entries use a backing file/device plus the pseudo mount point
		// "none"; they are not mount points and must not produce mount warnings.
		if len(f) < 4 || f[0] == "none" || strings.EqualFold(f[2], "swap") {
			continue
		}
		opts := strings.Split(f[3], ",")
		out = append(out, model.MountCheck{MountPoint: decodeMountPath(f[1]), Source: decodeMountPath(f[0]), FSType: f[2], Options: opts, Persistent: true})
	}
	return out
}

func decodeMountPath(path string) string { return mountinfo.Unescape(path) }
