package process

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestOwnChildrenAreNotHostFaults covers a false positive observed in a real
// run: glimpse executes optional commands concurrently with this /proc scan,
// so a command that has exited but has not yet been reaped is legitimately a
// zombie for as long as the scan takes. The report named glimpse itself as the
// zombie's parent while presenting it as a host finding.
func TestOwnChildrenAreNotHostFaults(t *testing.T) {
	self := os.Getpid()
	root := t.TempDir()
	write := func(pid, ppid int, state byte, comm string) {
		dir := filepath.Join(root, fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// pid (comm) state ppid ... 22 fields after comm.
		fields := fmt.Sprintf("%d (%s) %c %d", pid, comm, state, ppid)
		for i := 0; i < 22; i++ {
			fields += " 0"
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(fields), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(1, 0, 'S', "init")
	write(4242, self, 'Z', "journalctl") // glimpse's own unreaped child
	write(4243, self, 'D', "smartctl")   // glimpse's own blocked child
	write(5000, 1, 'Z', "realzombie")    // a genuine host zombie
	write(5001, 1, 'D', "realstuck")     // a genuine blocked task

	snapshot, err := Collect(context.Background(), root, 10)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Zombies != 1 {
		t.Errorf("Zombies = %d, want 1 (glimpse's own unreaped child must not count)", snapshot.Zombies)
	}
	if snapshot.Blocked != 1 {
		t.Errorf("Blocked = %d, want 1 (glimpse's own blocked child must not count)", snapshot.Blocked)
	}
	if snapshot.Processes != 5 {
		t.Errorf("Processes = %d, want 5: own children are still processes on this host", snapshot.Processes)
	}
	reported := zombies(snapshot.all, 10)
	if len(reported) != 1 || reported[0].PID != 5000 {
		t.Errorf("zombie identities = %+v, want only PID 5000", reported)
	}
	stuck := endpointDStateProcesses(snapshot.all, snapshot.all, 10)
	if len(stuck) != 1 || stuck[0].PID != 5001 {
		t.Errorf("D-state identities = %+v, want only PID 5001", stuck)
	}
}
