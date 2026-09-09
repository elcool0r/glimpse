package analyze

import (
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func TestCgroupExplicitInvalidSamplesSuppressFindings(t *testing.T) {
	falseValue := false
	max := uint64(100)
	report := model.Report{Metrics: model.Metrics{CPU: &model.CPU{}, Pressure: &model.Pressure{Memory: model.PressureResource{SomeAvg10: 5}}, CgroupV2: &model.CgroupV2{
		Available: true, MemoryOOMKillDelta: 100, MemoryEventsSampled: &falseValue,
		CPUUsageSecondsDelta: 1, CPUThrottledSecondsDelta: .5, CPUStatSampled: &falseValue,
		PIDsCurrent: 99, PIDsCurrentValid: &falseValue, PIDsMax: &max, PIDsMaxValid: &falseValue,
		MemoryCurrentBytes: 99, MemoryCurrentValid: &falseValue, MemoryMaxBytes: &max, MemoryMaxValid: &falseValue,
	}}}
	Report(&report)
	for _, id := range []string{"cgroup-oom-kill", "cgroup-cpu-throttling", "cgroup-pids-limit", "cgroup-memory-limit"} {
		if findingByID(report, id) != nil {
			t.Fatalf("invalid cgroup observation produced %s: %#v", id, report.Findings)
		}
	}
}

func TestCgroupMemoryLimitUsesOnlyLocalPressureOrLocalEvents(t *testing.T) {
	max := uint64(100)
	valid := true
	localZero := model.PressureResource{}
	report := model.Report{Metrics: model.Metrics{
		CPU:      &model.CPU{},
		Pressure: &model.Pressure{Memory: model.PressureResource{SomeAvg10: 25}},
		CgroupV2: &model.CgroupV2{Available: true, MemoryCurrentBytes: 96, MemoryCurrentValid: &valid, MemoryMaxBytes: &max, MemoryMaxValid: &valid, MemoryPressureValid: &valid, MemoryPressure: &localZero},
	}}
	Report(&report)
	if findingByID(report, "cgroup-memory-limit") != nil {
		t.Fatalf("host PSI must not be attributed to the cgroup: %#v", report.Findings)
	}
	report.Metrics.Pressure.Memory.SomeAvg10 = 0
	report.Metrics.CgroupV2.MemoryPressure.SomeAvg10 = 1.25
	Report(&report)
	if findingByID(report, "cgroup-memory-limit") == nil {
		t.Fatalf("local cgroup PSI must be evaluated independently: %#v", report.Findings)
	}
	invalid := false
	report.Metrics.CgroupV2.MemoryPressureValid = &invalid
	Report(&report)
	if findingByID(report, "cgroup-memory-limit") != nil {
		t.Fatalf("invalid local PSI created a cgroup finding: %#v", report.Findings)
	}
}
