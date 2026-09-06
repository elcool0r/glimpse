package cgroupv2

import (
	"context"
	"testing"
)

func TestCollectorRespectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Collect(ctx); err == nil {
		t.Fatal("expected cancelled context error")
	}
}

func TestParsePath(t *testing.T) {
	p, ok := ParsePath("0::/user.slice/user-1000.slice\n")
	if !ok || p != "/user.slice/user-1000.slice" {
		t.Fatalf("%q %v", p, ok)
	}
}
func TestParseKeyValues(t *testing.T) {
	got := ParseKeyValues("oom 2\nbad x\noom_kill 1\n")
	if got["oom"] != 2 || got["oom_kill"] != 1 {
		t.Fatal(got)
	}
}
func TestCounterDelta(t *testing.T) {
	if counterDelta(5, 3) != 0 || counterDelta(3, 5) != 2 {
		t.Fatal("bad delta")
	}
}
