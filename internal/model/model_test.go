package model

import (
	"encoding/json"
	"strings"
	"testing"
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
