package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/elcool0r/glimpse/internal/analyze"
	"github.com/elcool0r/glimpse/internal/collect/zfs"
	"github.com/elcool0r/glimpse/internal/model"
)

func TestZFSLeafErrorIsVisibleAfterAnalyze(t *testing.T) {
	pools := zfs.ParseStatus("pool: tank\n state: ONLINE\nconfig:\n tank ONLINE 0 0 0\n /dev/sda ONLINE 0 0 7\nerrors: No known data errors\n")
	report := model.Report{Metrics: model.Metrics{ZFSPools: pools}}
	report.Metrics.ZFSPools[0].VdevErrors[0].Approximate = true
	analyze.Report(&report)
	var output bytes.Buffer
	Write(&output, report, Options{Width: 120})
	text := output.String()
	if !strings.Contains(text, "ZFS WARN") || !strings.Contains(text, "/dev/sda") {
		t.Fatalf("leaf error hidden from normal report: %s", text)
	}

	var verbose bytes.Buffer
	Write(&verbose, report, Options{Verbose: true, Width: 120})
	if !strings.Contains(verbose.String(), "Vdev /dev/sda") || !strings.Contains(verbose.String(), "checksum 7") || !strings.Contains(verbose.String(), "some counters approximate") {
		t.Fatalf("leaf error missing from verbose report: %s", verbose.String())
	}

	var quiet bytes.Buffer
	Write(&quiet, report, Options{Quiet: true, Width: 120})
	if !strings.Contains(quiet.String(), "ZFS WARN") || !strings.Contains(quiet.String(), "/dev/sda") {
		t.Fatalf("leaf error hidden by quiet report: %s", quiet.String())
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.Report
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Metrics.ZFSPools) != 1 || decoded.Metrics.ZFSPools[0].ReadErrors != 0 || len(decoded.Metrics.ZFSPools[0].VdevErrors) != 1 || decoded.Metrics.ZFSPools[0].VdevErrors[0].ChecksumErrors != 7 {
		t.Fatalf("JSON lost root/leaf ZFS distinction: %s", encoded)
	}
}
