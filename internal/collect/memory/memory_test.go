package memory

import (
	"context"
	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseMemInfo(t *testing.T) {
	fixture, err := os.Open("testdata/meminfo.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	got, err := ParseMemInfo(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 1024*1024 || got.Used() != 624*1024 || got.SwapUsed() != 40*1024 {
		t.Fatalf("unexpected meminfo: %#v", got)
	}
}

func TestParseSwappiness(t *testing.T) {
	for _, tt := range []struct {
		raw  string
		want uint64
		ok   bool
	}{{"60\n", 60, true}, {"0", 0, true}, {"201", 0, false}, {"no", 0, false}} {
		got, err := parseSwappiness(tt.raw)
		if (err == nil) != tt.ok || err == nil && got != tt.want {
			t.Fatalf("parseSwappiness(%q) = %d, %v", tt.raw, got, err)
		}
	}
}

func TestParseVMStat(t *testing.T) {
	fixture, err := os.Open("testdata/vmstat.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	got, err := ParseVMStat(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if got != (VMStat{PageIn: 1, PageOut: 2, SwapIn: 3, SwapOut: 4, PageFault: 5, MajorFault: 6}) {
		t.Fatalf("unexpected VM stat: %#v", got)
	}
}

func TestParsePressure(t *testing.T) {
	got, err := ParsePressure(strings.NewReader("some avg10=0.01 avg60=0.02 avg300=0.03 total=100\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Some.Total != 100 || got.Full == nil || got.Full.Total != 2 {
		t.Fatalf("unexpected pressure: %#v", got)
	}
}

func TestParsePressureAcceptsZeroRecord(t *testing.T) {
	got, err := ParsePressure(strings.NewReader("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"))
	if err != nil || got.Some.Total != 0 {
		t.Fatalf("zero pressure record rejected: %#v, %v", got, err)
	}
}

func TestBetweenCounterReset(t *testing.T) {
	start := Snapshot{At: time.Unix(1, 0), VM: VMStat{SwapIn: 10, MajorFault: 1}}
	end := Snapshot{At: time.Unix(2, 0), VM: VMStat{SwapIn: 5, MajorFault: 4}}
	got, err := Between(start, end)
	if err != nil {
		t.Fatal(err)
	}
	if got.SwapIn != 0 || got.MajorFault != 3 {
		t.Fatalf("unexpected delta: %#v", got)
	}
}

func TestMissingProcFilesDoNotCreateSnapshot(t *testing.T) {
	data, err := (Collector{ProcRoot: t.TempDir()}).Collect(context.Background())
	if err == nil || data.Snapshot != nil {
		t.Fatalf("fatal error created snapshot: %+v, %v", data, err)
	}
}

func TestMissingBaselinePreservesGauges(t *testing.T) {
	last := collect.Data{Memory: &model.Memory{TotalBytes: 4096}}
	got, err := (Collector{}).Delta(collect.Data{}, last)
	if err == nil || got.Memory == nil || got.Memory.TotalBytes != 4096 || got.Memory.Sampled == nil || *got.Memory.Sampled {
		t.Fatalf("invalid fallback: %+v %v", got, err)
	}
}

func TestMalformedOptionalPSIPreservesCore(t *testing.T) {
	root := t.TempDir()
	for name, contents := range map[string]string{"meminfo": "MemTotal: 4096 kB\nMemAvailable: 3000 kB\n", "vmstat": "pswpin 0\npswpout 0\n", "pressure/memory": "broken\n"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := (Collector{ProcRoot: root}).Collect(context.Background())
	if err == nil || got.Memory == nil || got.Snapshot == nil {
		t.Fatalf("lost core facts: %+v %v", got, err)
	}
}
