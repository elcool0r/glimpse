package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestZeroBootTimeIsOmittedFromJSON(t *testing.T) {
	b, err := json.Marshal(Host{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "boot_time") {
		t.Fatalf("zero boot time leaked into JSON: %s", b)
	}
}

func TestMetricsOmitOptionalMilestoneTwoCategories(t *testing.T) {
	b, err := json.Marshal(Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"disks", "tcp", "device_health", "time_sync", "resources", "privileges", "trends"} {
		if strings.Contains(string(b), field) {
			t.Fatalf("empty optional category leaked into JSON: %s", b)
		}
	}
}

// Report JSON is a public API. Keep this compact representative document as a
// golden contract so accidental field renames, unit shape changes, or omitted
// required top-level fields fail loudly.
func TestReportJSONGoldenContract(t *testing.T) {
	report := Report{
		SchemaVersion:         SchemaVersion,
		GeneratedAt:           time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC),
		SampleDurationSeconds: 2.5,
		Host:                  Host{Hostname: "node-1", OS: "Linux", Architecture: "amd64", CPUCount: 4},
		Metrics:               Metrics{CPU: &CPU{Utilization: .5}},
		Findings:              []Finding{},
		Score:                 Score{Value: 100, Status: SeverityOK, Label: "EXCELLENT"},
		Collection:            []CollectionStatus{{Collector: "cpu", Status: "ok"}},
	}

	got, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"schema_version":1,"generated_at":"2024-01-02T03:04:05Z","sample_duration_seconds":2.5,"host":{"hostname":"node-1","os":"Linux","architecture":"amd64","cpu_count":4,"is_root":false},"metrics":{"cpu":{"utilization":0.5,"user":0,"system":0,"iowait":0,"steal":0,"load1":0,"load5":0,"load15":0}},"findings":[],"score":{"value":100,"status":"ok","label":"EXCELLENT"},"collection":[{"collector":"cpu","status":"ok"}]}`
	if string(got) != want {
		t.Fatalf("report JSON contract changed:\n got: %s\nwant: %s", got, want)
	}
}
