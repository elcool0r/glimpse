// Package storagehealth parses optional SMART and NVMe health command output.
package storagehealth

import (
	"encoding/json"
	"fmt"
)

// Device is a normalized subset of device health counters. Temperatures use
// Celsius; the remaining counts are current lifetime counters, not deltas.
type Device struct {
	Name                    string
	Kind                    string
	OverallPassed           *bool
	ReallocatedSectors      uint64
	PendingSectors          uint64
	OfflineUncorrectable    uint64
	CRCErrors               uint64
	TemperatureC            *float64
	CriticalWarning         uint64
	AvailableSpare          *float64
	AvailableSpareThreshold *float64
	PercentageUsed          *float64
	MediaErrors             uint64
	UnsafeShutdowns         uint64
}

// ParseSmartJSON accepts smartctl --json --xall output. It intentionally
// ignores vendor-specific attributes except the ATA IDs with stable meaning.
func ParseSmartJSON(name string, raw []byte) (Device, error) {
	var document smartDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return Device{}, fmt.Errorf("parse smartctl JSON: %w", err)
	}
	result := Device{Name: name, Kind: document.Device.Type}
	if document.SmartStatus.Passed != nil {
		result.OverallPassed = document.SmartStatus.Passed
	}
	if document.Temperature.Current != nil {
		result.TemperatureC = document.Temperature.Current
	}
	for _, attribute := range document.ATAAttributes.Table {
		switch attribute.ID {
		case 5:
			result.ReallocatedSectors = attribute.Raw.Value
		case 197:
			result.PendingSectors = attribute.Raw.Value
		case 198:
			result.OfflineUncorrectable = attribute.Raw.Value
		case 199:
			result.CRCErrors = attribute.Raw.Value
		}
	}
	if document.NVMeLog != nil {
		result.Kind = "nvme"
		result.CriticalWarning = document.NVMeLog.CriticalWarning
		result.MediaErrors = document.NVMeLog.MediaErrors
		result.UnsafeShutdowns = document.NVMeLog.UnsafeShutdowns
		if document.NVMeLog.AvailableSpare != nil {
			result.AvailableSpare = document.NVMeLog.AvailableSpare
		}
		if document.NVMeLog.AvailableSpareThreshold != nil {
			result.AvailableSpareThreshold = document.NVMeLog.AvailableSpareThreshold
		}
		if document.NVMeLog.PercentageUsed != nil {
			result.PercentageUsed = document.NVMeLog.PercentageUsed
		}
	}
	return result, nil
}

// ParseNVMeJSON accepts nvme smart-log -o json output. The nvme CLI reports
// temperature in Celsius while smartctl's NVMe JSON reports Kelvin; this
// parser is deliberately only for the nvme CLI format.
func ParseNVMeJSON(name string, raw []byte) (Device, error) {
	var document nvmeDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return Device{}, fmt.Errorf("parse nvme JSON: %w", err)
	}
	result := Device{Name: name, Kind: "nvme", CriticalWarning: document.CriticalWarning,
		MediaErrors: document.MediaErrors, UnsafeShutdowns: document.UnsafeShutdowns}
	if document.Temperature != nil {
		result.TemperatureC = document.Temperature
	}
	if document.AvailableSpare != nil {
		result.AvailableSpare = document.AvailableSpare
	}
	if document.AvailableSpareThreshold != nil {
		result.AvailableSpareThreshold = document.AvailableSpareThreshold
	}
	if document.PercentageUsed != nil {
		result.PercentageUsed = document.PercentageUsed
	}
	return result, nil
}

type smartDocument struct {
	Device struct {
		Type string `json:"type"`
	} `json:"device"`
	SmartStatus struct {
		Passed *bool `json:"passed"`
	} `json:"smart_status"`
	Temperature struct {
		Current *float64 `json:"current"`
	} `json:"temperature"`
	ATAAttributes struct {
		Table []struct {
			ID  int `json:"id"`
			Raw struct {
				Value uint64 `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMeLog *nvmeDocument `json:"nvme_smart_health_information_log"`
}

type nvmeDocument struct {
	CriticalWarning         uint64   `json:"critical_warning"`
	Temperature             *float64 `json:"temperature"`
	AvailableSpare          *float64 `json:"available_spare"`
	AvailableSpareThreshold *float64 `json:"available_spare_threshold"`
	PercentageUsed          *float64 `json:"percentage_used"`
	MediaErrors             uint64   `json:"media_errors"`
	UnsafeShutdowns         uint64   `json:"unsafe_shutdowns"`
}
