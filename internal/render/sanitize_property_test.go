package render

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/model"
)

// hostile is injected into every string field a report can carry. Each piece
// is something a real host can actually produce: the kernel escapes only
// space, tab, newline and backslash in /proc/self/mountinfo, so a literal ESC
// in a directory name arrives intact, and mountinfo.Unescape turns \012 back
// into a real newline.
const hostile = "ev\x1b[31mil\nSECOND\rCARRIAGE\x07BELL​ZWSP\ttab"

// TestRenderSanitizesEveryStringField is a property test rather than a list of
// call sites. cleanText was applied correctly in roughly sixty places and
// forgotten in one -- the "Diagnostic:" line, which is printed for every WARN
// and CRIT finding -- so a test that enumerates the places it is used could
// never have caught it. Walking the model reflectively means a field added
// tomorrow is covered without anyone remembering to extend this test.
func TestRenderSanitizesEveryStringField(t *testing.T) {
	for _, mode := range []struct {
		name    string
		options Options
	}{
		{"compact", Options{Width: 100}},
		{"verbose", Options{Width: 100, Verbose: true, Events: true, EventsAll: true}},
		{"narrow", Options{Width: 40, Verbose: true, Events: true}},
		{"quiet", Options{Width: 100, Quiet: true}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			report := hostileReport()
			analyze.Report(&report)
			var buf bytes.Buffer
			Write(&buf, report, mode.options)
			out := buf.String()
			if out == "" {
				t.Fatal("renderer produced nothing; the property would be vacuous")
			}
			if !strings.Contains(out, "ev") {
				t.Fatal("hostile text never reached the output; the fixture is not exercising the renderer")
			}
			for index, r := range out {
				if r == '\n' {
					continue // the renderer's own line separator
				}
				if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
					t.Fatalf("control/format character %q survived to the output at byte %d\nline: %q",
						r, index, lineAround(out, index))
				}
			}
		})
	}
}

// TestRenderColorOutputEmitsOnlyItsOwnEscapes checks the same property with
// color enabled, where the renderer legitimately writes ESC itself: every
// escape sequence in the output must be a well-formed SGR sequence, so
// injected text cannot smuggle a cursor-movement or screen-clearing code in
// alongside them.
func TestRenderColorOutputEmitsOnlyItsOwnEscapes(t *testing.T) {
	report := hostileReport()
	analyze.Report(&report)
	var buf bytes.Buffer
	Write(&buf, report, Options{Width: 100, Verbose: true, Events: true, Color: true})
	out := buf.String()
	for i := 0; i < len(out); i++ {
		if out[i] != 0x1b {
			continue
		}
		end := strings.IndexByte(out[i:], 'm')
		if end < 0 || end > 12 || !strings.HasPrefix(out[i:], "\x1b[") {
			t.Fatalf("output carries an escape that is not a short SGR sequence at byte %d: %q", i, lineAround(out, i))
		}
		for _, b := range out[i+2 : i+end] {
			if b != ';' && (b < '0' || b > '9') {
				t.Fatalf("SGR sequence at byte %d has a non-numeric parameter: %q", i, out[i:i+end+1])
			}
		}
		i += end
	}
}

func lineAround(s string, index int) string {
	start := strings.LastIndexByte(s[:index], '\n') + 1
	end := strings.IndexByte(s[index:], '\n')
	if end < 0 {
		return s[start:]
	}
	return s[start : index+end]
}

// hostileReport builds a report whose every string field carries the hostile
// sentinel, by walking the model with reflection.
func hostileReport() model.Report {
	report := model.Report{
		SchemaVersion:         model.SchemaVersion,
		GeneratedAt:           time.Now(),
		SampleDurationSeconds: 5,
	}
	poison(reflect.ValueOf(&report).Elem(), 0)
	// Reflection fills leaves but cannot know which combinations make the
	// renderer take its interesting branches, so pin the ones that matter.
	report.Host.CPUCount = 4
	report.Metrics.CPU.HostCPUCount = 4
	report.Metrics.CPU.Utilization = .99
	report.Metrics.CPU.Load1 = 40
	report.Metrics.Memory.TotalBytes = 1 << 30
	report.Metrics.Memory.AvailableFraction = .01
	report.Metrics.Filesystems[0].UsedFraction = .99
	report.Metrics.Filesystems[0].InodesTotal = 1000
	report.Metrics.Filesystems[0].InodesFree = 1
	report.Metrics.Disks[0].Utilization = .99
	report.Metrics.Disks[0].AverageQueueDepth = 9
	report.Metrics.Thermal[0].TemperatureC = 120
	report.Metrics.Thermal[0].CriticalC = 100
	report.Metrics.Processes.Zombies = 2
	report.Metrics.Systemd.Available = true
	report.Metrics.Kernel.Available = true
	report.Metrics.Kernel.Events[0].Kind = model.KindKernelPanic
	report.Metrics.Security.Available = true
	report.Metrics.CgroupV2.Available = true
	report.Metrics.NetworkState.Available = true
	report.Metrics.DeletedFiles.Available = true
	report.Metrics.Hardware.Available = true
	report.Metrics.ZFSPools[0].ReadErrors = 5
	report.Metrics.SoftwareRAID[0].State = hostile
	age := 60.0
	report.Metrics.Kernel.Events[0].AgeSeconds = &age
	report.Metrics.Containers[0].Containers[0].LogEvents[0].Kind = model.LogKindPanic
	report.Metrics.Containers[0].Containers[0].LogEvents[0].AgeSeconds = &age
	report.Metrics.PackageActivity[0].At = time.Now()
	report.Metrics.Logins[0].At = time.Now()
	report.Metrics.SudoCommands[0].At = time.Now()
	report.Metrics.SudoCommands[0].Command = hostile + strings.Repeat("ä", 120)
	return report
}

// poison sets every reachable string to the hostile sentinel and materializes
// one element for every pointer and slice, so no field is skipped merely
// because the zero value happens to be empty.
func poison(v reflect.Value, depth int) {
	if depth > 8 || !v.CanSet() {
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(hostile)
	case reflect.Ptr:
		if v.Type().Elem() == reflect.TypeOf(time.Time{}) {
			now := time.Now()
			v.Set(reflect.ValueOf(&now))
			return
		}
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		poison(v.Elem(), depth+1)
	case reflect.Slice:
		if v.Len() == 0 {
			v.Set(reflect.MakeSlice(v.Type(), 2, 2))
		}
		for i := 0; i < v.Len(); i++ {
			poison(v.Index(i), depth+1)
		}
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return
		}
		m := reflect.MakeMap(v.Type())
		entry := reflect.New(v.Type().Elem()).Elem()
		poison(entry, depth+1)
		m.SetMapIndex(reflect.ValueOf(hostile), entry)
		v.Set(m)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			v.Set(reflect.ValueOf(time.Now()))
			return
		}
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath != "" {
				continue // unexported
			}
			poison(v.Field(i), depth+1)
		}
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		if v.Int() == 0 {
			v.SetInt(3)
		}
	case reflect.Uint64:
		if v.Uint() == 0 {
			v.SetUint(3)
		}
	case reflect.Float64:
		if v.Float() == 0 {
			v.SetFloat(3)
		}
	}
	_ = fmt.Sprint
}
