// Package thermal collects Linux hwmon and thermal-zone temperatures.
package thermal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Sensor temperatures and thresholds are Celsius. A nil threshold means sysfs did not expose it.
type Sensor struct {
	Name         string
	Label        string
	TemperatureC float64
	CriticalC    *float64
	MaximumC     *float64
	Source       string
}

func ParseMilliCelsius(s string) (float64, error) {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, err
	}
	return float64(v) / 1000, nil
}

func Collect(ctx context.Context, sysRoot string) ([]Sensor, error) {
	if sysRoot == "" {
		sysRoot = "/sys"
	}
	var sensors []Sensor
	hwmon, hwmonErr := collectHWMON(ctx, filepath.Join(sysRoot, "class/hwmon"))
	sensors = append(sensors, hwmon...)
	zones, zoneErr := collectZones(ctx, filepath.Join(sysRoot, "class/thermal"))
	sensors = append(sensors, zones...)
	if len(sensors) > 0 {
		sort.Slice(sensors, func(i, j int) bool { return sensors[i].Name+sensors[i].Label < sensors[j].Name+sensors[j].Label })
		return sensors, nil
	}
	if hwmonErr != nil && zoneErr != nil {
		return nil, errors.Join(hwmonErr, zoneErr)
	}
	return sensors, nil
}

func collectHWMON(ctx context.Context, root string) ([]Sensor, error) {
	dirs, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var result []Sensor
	for _, dir := range dirs {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		base := filepath.Join(root, dir.Name())
		info, statErr := os.Stat(base)
		if statErr != nil || !info.IsDir() {
			continue
		}
		name, _ := readString(filepath.Join(base, "name"))
		if name == "" {
			name = dir.Name()
		}
		inputs, _ := filepath.Glob(filepath.Join(base, "temp*_input"))
		for _, input := range inputs {
			temp, err := readTemperature(input)
			if err != nil {
				continue
			}
			stem := strings.TrimSuffix(input, "_input")
			label, _ := readString(stem + "_label")
			if label == "" {
				label = filepath.Base(stem)
			}
			s := Sensor{Name: name, Label: label, TemperatureC: temp, Source: "hwmon"}
			if v, err := readTemperature(stem + "_crit"); err == nil {
				s.CriticalC = &v
			}
			if v, err := readTemperature(stem + "_max"); err == nil {
				s.MaximumC = &v
			}
			result = append(result, s)
		}
	}
	return result, nil
}

func collectZones(ctx context.Context, root string) ([]Sensor, error) {
	dirs, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var result []Sensor
	for _, dir := range dirs {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		base := filepath.Join(root, dir.Name())
		info, statErr := os.Stat(base)
		if statErr != nil || !info.IsDir() || !strings.HasPrefix(dir.Name(), "thermal_zone") {
			continue
		}
		temp, err := readTemperature(filepath.Join(base, "temp"))
		if err != nil {
			continue
		}
		name, _ := readString(filepath.Join(base, "type"))
		if name == "" {
			name = dir.Name()
		}
		s := Sensor{Name: name, Label: "temperature", TemperatureC: temp, Source: "thermal_zone"}
		trips, _ := filepath.Glob(filepath.Join(base, "trip_point_*_temp"))
		for _, tempPath := range trips {
			stem := strings.TrimSuffix(tempPath, "_temp")
			tripType, typeErr := readString(stem + "_type")
			v, tempErr := readTemperature(tempPath)
			if typeErr != nil || tempErr != nil {
				continue
			}
			switch strings.ToLower(tripType) {
			case "critical":
				s.CriticalC = &v
			case "hot", "passive", "active":
				if s.MaximumC == nil || v < *s.MaximumC {
					s.MaximumC = &v
				}
			}
		}
		result = append(result, s)
	}
	return result, nil
}

func readTemperature(path string) (float64, error) {
	s, err := readString(path)
	if err != nil {
		return 0, err
	}
	return ParseMilliCelsius(s)
}
func readString(path string) (string, error) {
	b, err := os.ReadFile(path)
	return strings.TrimSpace(string(b)), err
}
