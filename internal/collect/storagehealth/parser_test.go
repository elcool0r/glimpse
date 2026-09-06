package storagehealth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSmartJSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "smartctl-ata.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSmartJSON("sda", raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.OverallPassed == nil || !*got.OverallPassed || got.ReallocatedSectors != 2 || got.PendingSectors != 3 || got.OfflineUncorrectable != 4 || got.CRCErrors != 5 {
		t.Fatalf("unexpected result: %#v", got)
	}
	if got.TemperatureC == nil || *got.TemperatureC != 31 {
		t.Fatalf("temperature: %#v", got.TemperatureC)
	}
}

func TestParseNVMeJSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "nvme-smart.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseNVMeJSON("nvme0", raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.CriticalWarning != 1 || got.MediaErrors != 4 || got.UnsafeShutdowns != 8 {
		t.Fatalf("counters: %#v", got)
	}
	if got.TemperatureC == nil || *got.TemperatureC != 34 || got.AvailableSpare == nil || *got.AvailableSpare != 95 || got.PercentageUsed == nil || *got.PercentageUsed != 6 {
		t.Fatalf("values: %#v", got)
	}
}

func TestParseSmartJSONSupportsNVMeLog(t *testing.T) {
	got, err := ParseSmartJSON("nvme0n1", []byte(`{"device":{"type":"nvme"},"nvme_smart_health_information_log":{"critical_warning":2,"available_spare":98,"percentage_used":7,"media_errors":3}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "nvme" || got.CriticalWarning != 2 || got.AvailableSpare == nil || *got.AvailableSpare != 98 || got.MediaErrors != 3 {
		t.Fatalf("got %#v", got)
	}
}

func TestParseSmartJSONRejectsInvalid(t *testing.T) {
	if _, err := ParseSmartJSON("sda", []byte("{")); err == nil {
		t.Fatal("expected error")
	}
}
