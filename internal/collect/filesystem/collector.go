package filesystem

import (
	"context"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

// Collector adapts Linux mount facts to the shared normalized model.
type Collector struct{ ProcRoot string }

func (Collector) Name() string { return "filesystems" }

// Static marks filesystem capacity as a gauge: merge uses only the final
// observation, so a baseline statfs sweep is discarded work.
func (Collector) Static() {}

func (c Collector) Collect(ctx context.Context) (collect.Data, error) {
	usages, err := Collect(ctx, c.ProcRoot)
	filesystems := make([]model.Filesystem, 0, len(usages))
	for _, usage := range usages {
		filesystems = append(filesystems, model.Filesystem{
			MountPoint: usage.Target, Filesystem: usage.Source, Type: usage.Type,
			TotalBytes: usage.TotalBytes, AvailableBytes: usage.AvailableBytes,
			UsedFraction: usage.UsedFraction, InodesTotal: usage.Inodes,
			InodesFree: usage.FreeInodes, ReadOnly: usage.ReadOnly,
		})
	}
	return collect.Data{Filesystems: filesystems}, err
}
