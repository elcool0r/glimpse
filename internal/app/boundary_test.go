package app

import (
	"context"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
	"github.com/elcool0r/glimpse/internal/model"
)

type boundaryRecorder struct {
	name  string
	seen  []collect.Boundary
	plain int
}

func (b *boundaryRecorder) Name() string { return b.name }

func (b *boundaryRecorder) Collect(context.Context) (collect.Data, error) {
	b.plain++
	return collect.Data{Snapshot: 0}, nil
}

func (b *boundaryRecorder) CollectAt(_ context.Context, boundary collect.Boundary) (collect.Data, error) {
	b.seen = append(b.seen, boundary)
	return collect.Data{Snapshot: len(b.seen)}, nil
}

func (b *boundaryRecorder) Delta(collect.Data, collect.Data) (collect.Data, error) {
	return collect.Data{Memory: &model.Memory{TotalBytes: 1}}, nil
}

// TestBoundaryCollectorSeesBothBoundaries checks the lifecycle half of the
// contract: a delta collector still runs twice, but it is told which boundary
// it is at so it can skip work merge would discard.
func TestBoundaryCollectorSeesBothBoundaries(t *testing.T) {
	recorder := &boundaryRecorder{name: "recorder"}
	report := Run(context.Background(), Config{Duration: 0, SampleInterval: time.Millisecond}, []collect.Collector{recorder})
	if len(recorder.seen) != 2 {
		t.Fatalf("CollectAt called %d times, want 2: %v", len(recorder.seen), recorder.seen)
	}
	if recorder.seen[0] != collect.BoundaryBaseline || recorder.seen[1] != collect.BoundaryFinal {
		t.Fatalf("boundaries = %v, want [baseline final]", recorder.seen)
	}
	if recorder.plain != 0 {
		t.Errorf("Collect was called %d times; a BoundaryCollector must be reached through CollectAt", recorder.plain)
	}
	if report.Metrics.Memory == nil {
		t.Error("Delta result did not reach the report")
	}
}

type plainCollector struct{ calls int }

func (p *plainCollector) Name() string { return "plain" }
func (p *plainCollector) Collect(context.Context) (collect.Data, error) {
	p.calls++
	return collect.Data{Memory: &model.Memory{TotalBytes: 1}}, nil
}
func (p *plainCollector) Delta(_, last collect.Data) (collect.Data, error) { return last, nil }

// TestPlainCollectorUnaffected keeps the opt-in nature explicit: a collector
// that does not implement BoundaryCollector is observed exactly as before.
func TestPlainCollectorUnaffected(t *testing.T) {
	plain := &plainCollector{}
	Run(context.Background(), Config{Duration: 0, SampleInterval: time.Millisecond}, []collect.Collector{plain})
	if plain.calls != 2 {
		t.Fatalf("Collect called %d times, want 2", plain.calls)
	}
}
