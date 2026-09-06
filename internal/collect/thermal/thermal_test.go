package thermal

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseMilliCelsius(t *testing.T) {
	got, err := ParseMilliCelsius(" 42500\n")
	if err != nil || got != 42.5 {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := ParseMilliCelsius("hot"); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectFollowsSymlinkedThermalZoneAndTripTypes(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "devices", "zone0")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{"temp": "42000\n", "type": "cpu-thermal\n", "trip_point_0_temp": "90000\n", "trip_point_0_type": "passive\n", "trip_point_1_temp": "100000\n", "trip_point_1_type": "critical\n"} {
		if err := os.WriteFile(filepath.Join(real, path), []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	zoneRoot := filepath.Join(root, "class", "thermal")
	if err := os.MkdirAll(zoneRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(zoneRoot, "thermal_zone0")); err != nil {
		t.Fatal(err)
	}
	sensors, err := Collect(context.Background(), root)
	if err != nil || len(sensors) != 1 || sensors[0].CriticalC == nil || *sensors[0].CriticalC != 100 || sensors[0].MaximumC == nil || *sensors[0].MaximumC != 90 {
		t.Fatalf("unexpected symlink/trip result: %#v, %v", sensors, err)
	}
}
