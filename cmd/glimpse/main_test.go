package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/app"
	"github.com/elcool0r/glimpse/internal/model"
	"github.com/elcool0r/glimpse/internal/render"
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

func TestInterruptedUnknownAssessmentAgreesAcrossTerminalJSONAndExitCode(t *testing.T) {
	report := model.Report{
		SchemaVersion: model.SchemaVersion,
		Score:         model.Score{Status: model.SeverityUnknown, Label: "INSUFFICIENT DATA"},
		Collection:    []model.CollectionStatus{{Collector: "sampling", Status: "error", Detail: "context deadline exceeded"}},
	}

	for _, quiet := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		code := writeReport(&stdout, &stderr, report, false, false, render.Options{ASCII: true, Quiet: quiet})
		if code != 3 {
			t.Fatalf("quiet=%t terminal exit code = %d, want 3", quiet, code)
		}
		if !strings.Contains(strings.Join(strings.Fields(stdout.String()), " "), "Assessment UNKNOWN INSUFFICIENT DATA: Sampling was interrupted; the health assessment is incomplete.") {
			t.Fatalf("quiet=%t missing interrupted assessment:\n%s", quiet, stdout.String())
		}
	}

	var stdout, stderr bytes.Buffer
	if code := writeReport(&stdout, &stderr, report, true, false, render.Options{}); code != 3 {
		t.Fatalf("JSON exit code = %d, want 3", code)
	}
	var got model.Report
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode JSON report: %v\n%s", err, stdout.String())
	}
	if got.Score.Status != model.SeverityUnknown || got.Score.Label != "INSUFFICIENT DATA" {
		t.Fatalf("JSON lost unknown score: %+v", got.Score)
	}
	if len(got.Collection) != 1 || got.Collection[0].Collector != "sampling" || got.Collection[0].Status != "error" {
		t.Fatalf("JSON lost sampling failure: %+v", got.Collection)
	}
}

// The bash completion word list is generated from the registered flags
// rather than a hand-maintained string precisely so a new flag can't be
// added without appearing here too, the way --quiet and --events once did.
func TestBashCompletionListsEveryRegisteredFlag(t *testing.T) {
	fs := flag.NewFlagSet("glimpse", flag.ContinueOnError)
	registerFlags(fs)
	script := bashCompletionScript(fs)
	fs.VisitAll(func(f *flag.Flag) {
		if !strings.Contains(script, "--"+f.Name) {
			t.Errorf("bash completion is missing --%s", f.Name)
		}
	})
	if !strings.Contains(script, "--help") {
		t.Error("bash completion is missing --help")
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

func TestNoProxyFlagDefaultsFalseAndCanBeEnabled(t *testing.T) {
	fs := flag.NewFlagSet("glimpse", flag.ContinueOnError)
	f := registerFlags(fs)
	if *f.noProxy {
		t.Fatal("--no-proxy default must preserve environment proxy support")
	}
	if err := fs.Parse([]string{"--no-proxy"}); err != nil || !*f.noProxy {
		t.Fatalf("--no-proxy was not parsed: value=%t err=%v", *f.noProxy, err)
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
	progress := progressWriter(&output, true)
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

func TestProgressWithoutColorUsesNoANSIEscapes(t *testing.T) {
	var output bytes.Buffer
	progress := progressWriter(&output, false)
	progress(app.Progress{Phase: "baseline"})
	progress(app.Progress{Phase: "sampling", Elapsed: 5 * time.Second, Duration: 60 * time.Second})
	progress(app.Progress{Phase: "final"})
	progress(app.Progress{Phase: "complete"})

	got := output.String()
	if strings.Contains(got, "\x1b") {
		t.Fatalf("no-color progress contains ANSI escape: %q", got)
	}
	if !strings.Contains(got, "Sampling health data: 05s / 60s") || !strings.HasSuffix(got, "\n") {
		t.Fatalf("unexpected no-color progress output: %q", got)
	}
}

func TestProgressActivationUsesStderrTTYAndExcludesJSON(t *testing.T) {
	for _, tt := range []struct {
		name                  string
		jsonOutput, stderrTTY bool
		want                  bool
	}{
		{name: "terminal stderr", stderrTTY: true, want: true},
		{name: "redirected stderr", stderrTTY: false, want: false},
		{name: "json terminal stderr", jsonOutput: true, stderrTTY: true, want: false},
		{name: "json redirected stderr", jsonOutput: true, stderrTTY: false, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := progressEnabled(tt.jsonOutput, tt.stderrTTY); got != tt.want {
				t.Fatalf("progressEnabled(json=%t, stderrTTY=%t) = %t, want %t", tt.jsonOutput, tt.stderrTTY, got, tt.want)
			}
		})
	}
}

func TestProgressColorPolicyHonorsBothDisableMechanisms(t *testing.T) {
	for _, tt := range []struct {
		name               string
		noColor            bool
		noColorEnvironment string
		want               bool
	}{
		{name: "color enabled", want: true},
		{name: "no-color flag", noColor: true, want: false},
		{name: "NO_COLOR", noColorEnvironment: "1", want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := progressColorEnabled(tt.noColor, tt.noColorEnvironment); got != tt.want {
				t.Fatalf("progressColorEnabled(noColor=%t, NO_COLOR=%q) = %t, want %t", tt.noColor, tt.noColorEnvironment, got, tt.want)
			}
		})
	}
}
