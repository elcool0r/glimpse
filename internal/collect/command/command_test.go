package command

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestOutputCapTruncatesInsteadOfDiscarding(t *testing.T) {
	// Aborting the copy at the cap threw away everything already read, so a
	// chatty source produced no evidence at all rather than partial evidence.
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	result, err := Run(context.Background(), Options{MaxOutput: 64},
		"sh", "-c", "printf 'A%.0s' $(seq 1 500)")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Output) != 64 {
		t.Fatalf("kept %d bytes, want the 64-byte prefix", len(result.Output))
	}
	if !result.Truncated {
		t.Fatal("truncation not reported")
	}
	if strings.Trim(string(result.Output), "A") != "" {
		t.Fatalf("unexpected content: %q", result.Output)
	}
}

func TestRunAppliesDefaultOutputCap(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	result, err := Run(context.Background(), Options{}, "sh", "-c", "i=0; while [ $i -le 1100000 ]; do printf A; i=$((i + 1)); done")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Output) != DefaultMaxOutput {
		t.Fatalf("kept %d bytes, want default cap %d", len(result.Output), DefaultMaxOutput)
	}
	if !result.Truncated {
		t.Fatal("default output cap did not report truncation")
	}
}

func TestRunReturnsPromptlyWhenTheChildIgnoresCancellation(t *testing.T) {
	// A context can request cancellation, but Wait blocks until the process
	// releases its pipes. A device command stuck in uninterruptible sleep never
	// does, which is exactly the failing hardware this tool exists to report on.
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	// The child ignores SIGKILL's effect on its grandchild, which keeps the
	// inherited stdout pipe open after the child itself is killed.
	_, err := Run(ctx, Options{}, "sh", "-c", "sleep 30 & sleep 30")
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("expected the bounded run to fail")
	}
	if elapsed > WaitDelay+2*time.Second {
		t.Fatalf("Run waited %s on a process holding its pipes open", elapsed)
	}
}

func TestOutputInheritsEnvironmentUnlessReplaced(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	t.Setenv("GLIMPSE_COMMAND_TEST", "inherited")
	out, err := Output(context.Background(), "sh", "-c", "printf %s \"$GLIMPSE_COMMAND_TEST\"")
	if err != nil || string(out) != "inherited" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	result, err := Run(context.Background(), Options{Env: []string{"GLIMPSE_COMMAND_TEST=replaced"}},
		"sh", "-c", "printf %s \"$GLIMPSE_COMMAND_TEST\"")
	if err != nil || string(result.Output) != "replaced" {
		t.Fatalf("out=%q err=%v", result.Output, err)
	}
}

func TestRunForcesStableCLocale(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	t.Setenv("LANG", "de_DE.UTF-8")
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	result, err := Run(context.Background(), Options{}, "sh", "-c", "printf '%s|%s' \"$LC_ALL\" \"$LANG\"")
	if err != nil || string(result.Output) != "C|C" {
		t.Fatalf("out=%q err=%v, want C|C", result.Output, err)
	}
	result, err = Run(context.Background(), Options{Env: []string{"LANG=fr_FR.UTF-8", "LC_ALL=fr_FR.UTF-8", "GLIMPSE_COMMAND_TEST=replaced"}}, "sh", "-c", "printf '%s|%s|%s' \"$LC_ALL\" \"$LANG\" \"$GLIMPSE_COMMAND_TEST\"")
	if err != nil || string(result.Output) != "C|C|replaced" {
		t.Fatalf("out=%q err=%v, want C|C|replaced", result.Output, err)
	}
}
