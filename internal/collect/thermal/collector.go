package thermal

import (
	"context"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

type Collector struct{ SysRoot string }

func (Collector) Name() string { return "thermal" }

// Static marks sensor temperatures as gauges.
func (Collector) Static() {}

func (c Collector) Collect(ctx context.Context) (collect.Data, error) {
	sensors, err := Collect(ctx, c.SysRoot)
	if err != nil {
		return collect.Data{}, err
	}
	thermal := make([]model.Thermal, 0, len(sensors))
	for _, sensor := range sensors {
		metric := model.Thermal{Name: sensor.Name + ": " + sensor.Label, TemperatureC: sensor.TemperatureC}
		if sensor.CriticalC != nil {
			metric.CriticalC = *sensor.CriticalC
		}
		if sensor.MaximumC != nil {
			metric.MaximumC = *sensor.MaximumC
		}
		thermal = append(thermal, metric)
	}
	return collect.Data{Thermal: thermal}, nil
}
