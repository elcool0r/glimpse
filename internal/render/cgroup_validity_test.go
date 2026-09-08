package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func TestCgroupVerboseShowsMeasuredZeroAndUnlimited(t *testing.T) {
	trueValue := true
	report := model.Report{Metrics: model.Metrics{CgroupV2: &model.CgroupV2{
		Available: true, MemoryCurrentValid: &trueValue, PIDsCurrentValid: &trueValue,
		MemoryMaxValid: &trueValue, PIDsMaxValid: &trueValue, MemoryEventsSampled: &trueValue, CPUStatSampled: &trueValue,
		MemoryCurrentBytes: 0, PIDsCurrent: 0,
	}}}
	var output bytes.Buffer
	Write(&output, report, Options{ASCII: true, Verbose: true})
	text := output.String()
	for _, want := range []string{"Memory current OK  0 bytes", "Memory limit OK  unlimited", "PID limit OK  unlimited"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
}

func TestCgroupVerboseShowsUnavailableWithoutInventingUsage(t *testing.T) {
	falseValue := false
	max := uint64(100)
	report := model.Report{Metrics: model.Metrics{CgroupV2: &model.CgroupV2{
		Available: true, MemoryCurrentValid: &falseValue, MemoryMaxValid: &falseValue,
		PIDsCurrentValid: &falseValue, PIDsMaxValid: &falseValue,
		MemoryEventsSampled: &falseValue, CPUStatSampled: &falseValue,
		MemoryMaxBytes: &max,
	}}}
	var output bytes.Buffer
	Write(&output, report, Options{ASCII: true, Verbose: true})
	text := output.String()
	for _, want := range []string{"Memory current UNKNOWN  unavailable", "Memory limit UNKNOWN  unavailable", "PID limit UNKNOWN  unavailable", "Memory events UNKNOWN  sample unavailable", "CPU statistics UNKNOWN  sample unavailable"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
}

func TestCgroupVerboseInvalidCurrentDoesNotRenderZeroUsage(t *testing.T) {
	falseValue, trueValue := false, true
	max := uint64(100)
	report := model.Report{Metrics: model.Metrics{CgroupV2: &model.CgroupV2{
		Available: true, MemoryCurrentValid: &falseValue, MemoryMaxValid: &trueValue, MemoryMaxBytes: &max,
		PIDsCurrentValid: &falseValue, PIDsMaxValid: &trueValue, PIDsMax: &max,
	}}}
	var output bytes.Buffer
	Write(&output, report, Options{ASCII: true, Verbose: true})
	text := output.String()
	for _, want := range []string{"Memory limit UNKNOWN  100 bytes; usage unavailable", "PID limit UNKNOWN  unavailable/100"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "0% used") || strings.Contains(text, "0/100") {
		t.Fatalf("invalid current values were rendered as measured:\n%s", text)
	}
}
