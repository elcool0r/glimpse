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
