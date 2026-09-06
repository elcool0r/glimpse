package main

import (
	"bytes"
	"encoding/json"
	"github.com/elcool0r/glimpse/internal/model"
	"github.com/elcool0r/glimpse/internal/render"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/app"
)

func TestReportExitCodesIndependentOfFormat(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		for _, tt := range []struct {
			status model.Severity
			code   int
		}{{model.SeverityOK, 0}, {model.SeverityInfo, 0}, {model.SeverityWarning, 1}, {model.SeverityCritical, 2}, {model.SeverityUnknown, 3}} {
			var out, err bytes.Buffer
			report := model.Report{Score: model.Score{Status: tt.status}}
			code := writeReport(&out, &err, report, jsonOutput, false, render.Options{})
			if code != tt.code {
				t.Fatalf("json=%v status=%s code=%d", jsonOutput, tt.status, code)
			}
			if jsonOutput && !json.Valid(out.Bytes()) {
				t.Fatalf("invalid JSON: %s", out.String())
			}
		}
	}
}
func TestRequireLongOptions(t *testing.T) {
	if err := requireLongOptions([]string{"--quick", "--duration=5s"}); err != nil {
		t.Fatalf("long options unexpectedly rejected: %v", err)
	}
	if err := requireLongOptions([]string{"-quick"}); err == nil {
		t.Fatal("single-dash option must be rejected")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestFailedOutputReturnsFailure(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		var stderr bytes.Buffer
		if code := writeReport(brokenWriter{}, &stderr, model.Report{}, jsonOutput, false, render.Options{}); code != 3 {
			t.Fatalf("json=%v code=%d", jsonOutput, code)
		}
	}
}
func TestVerboseDiagnosticsAreSanitized(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := model.Report{Collection: []model.CollectionStatus{{Collector: "cpu", Status: "error", Detail: "bad\x1b[2J\nline"}}}
	writeReport(&stdout, &stderr, r, true, true, render.Options{})
	if strings.Contains(stderr.String(), "\x1b") || strings.Count(stderr.String(), "\n") != 1 {
		t.Fatalf("unsafe diagnostic: %q", stderr.String())
	}
}

func TestProgressIsOneTransientLine(t *testing.T) {
	var output bytes.Buffer
	progress := progressWriter(&output)
	progress(app.Progress{Phase: "baseline"})
	progress(app.Progress{Phase: "sampling", Elapsed: 5 * time.Second, Duration: 60 * time.Second})
	progress(app.Progress{Phase: "final"})
	progress(app.Progress{Phase: "complete"})
	got := output.String()
	for _, want := range []string{
		"\x1b[36mCollecting health data...\x1b[0m",
		"\r\x1b[2K\x1b[36mSampling health data: \x1b[37m05s / 60s\x1b[0m",
		"\r\x1b[2K\x1b[36mProcessing health data...\x1b[0m",
		"\r\x1b[2K",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("progress output missing %q: %q", want, got)
		}
	}
	if strings.Contains(got, "Sampling health data: 00s / 00s") {
		t.Fatalf("unexpected progress output: %q", output.String())
	}
}
