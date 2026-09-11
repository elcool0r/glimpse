package containers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/elcool0r/glimpse/internal/collect"
)

// TestBaselineBoundarySkipsLogReads covers the cost half of the boundary
// contract. Delta reads only the restart counters from the first observation,
// so reading every container's logs there spends up to logTotalTimeout (16s)
// per boundary on evidence merge then discards -- on a busy container host
// that could add more wall time than the entire default sampling window.
func TestBaselineBoundarySkipsLogReads(t *testing.T) {
	for _, c := range []struct {
		name     string
		boundary collect.Boundary
		wantLogs bool
	}{
		{"baseline", collect.BoundaryBaseline, false},
		{"final", collect.BoundaryFinal, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var logCalls int
			collector := &Collector{
				lookPath: func(name string) (string, error) {
					if name == "docker" {
						return "/usr/bin/docker", nil
					}
					return "", errNotFound{}
				},
				run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
					switch {
					case contains(args, "ps"):
						return []byte("abc123\n"), nil
					case contains(args, "inspect"):
						return []byte(`{"Id":"abc123","Name":"/web","State":{"Status":"running","Restarting":false},"RestartCount":2}` + "\n"), nil
					}
					return nil, nil
				},
				runLogs: func(context.Context, []string, string) ([]byte, bool, error) {
					logCalls++
					return []byte("2024-01-01T00:00:00Z panic: boom\n"), false, nil
				},
			}
			data, err := collector.CollectAt(context.Background(), c.boundary)
			if err != nil {
				t.Fatal(err)
			}
			if (logCalls > 0) != c.wantLogs {
				t.Fatalf("%d log reads at the %s boundary, wantLogs=%v", logCalls, c.name, c.wantLogs)
			}
			// Either way the restart counters Delta needs must be present.
			snap, ok := data.Snapshot.(snapshot)
			if !ok || snap.restarts["docker:abc123"] != 2 {
				t.Fatalf("baseline must still carry the counters Delta reads: %+v", data.Snapshot)
			}
		})
	}
}

// TestLogBudgetChargesElapsedTime pins the accounting fix: a runtime that
// finishes quickly must not consume the share a later runtime would need.
func TestLogBudgetChargesElapsedTime(t *testing.T) {
	collector := &Collector{
		LogTotalTimeout: 200 * time.Millisecond,
		lookPath: func(name string) (string, error) {
			return "/usr/bin/" + name, nil
		},
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			switch {
			case contains(args, "ps"):
				return []byte("abc123\n"), nil
			case contains(args, "inspect"):
				return []byte(`{"Id":"abc123","Name":"/web","State":{"Status":"running"},"RestartCount":0}` + "\n"), nil
			}
			return nil, nil
		},
		runLogs: func(context.Context, []string, string) ([]byte, bool, error) {
			return []byte("ok\n"), false, nil
		},
	}
	data, err := collector.CollectAt(context.Background(), collect.BoundaryFinal)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Containers) != 2 {
		t.Fatalf("expected both runtimes to be observed, got %d", len(data.Containers))
	}
	for _, runtime := range data.Containers {
		if runtime.LogsChecked == 0 {
			t.Errorf("%s read no logs; the first runtime consumed the whole budget", runtime.Runtime)
		}
	}
}

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

func contains(args []string, want string) bool {
	for _, arg := range args {
		if arg == want || strings.HasSuffix(arg, "/"+want) {
			return true
		}
	}
	return false
}
