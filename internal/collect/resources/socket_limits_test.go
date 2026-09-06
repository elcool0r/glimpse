package resources

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestCollectReadsSocketTableCeilings(t *testing.T) {
	files := map[string]string{
		"/proc/sys/net/ipv4/tcp_max_tw_buckets": "131072\n",
		"/proc/sys/net/ipv4/tcp_max_orphans":    "32768\n",
		"/proc/sys/net/core/somaxconn":          "4096\n",
	}
	c := &Collector{ProcRoot: "/proc", readFile: func(path string) ([]byte, error) {
		if raw, ok := files[path]; ok {
			return []byte(raw), nil
		}
		return nil, os.ErrNotExist
	}}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Resources == nil {
		t.Fatal("no resources collected")
	}
	if got.Resources.TimeWaitMaximum != 131072 {
		t.Errorf("tcp_max_tw_buckets = %d, want 131072", got.Resources.TimeWaitMaximum)
	}
	if got.Resources.OrphanMaximum != 32768 {
		t.Errorf("tcp_max_orphans = %d, want 32768", got.Resources.OrphanMaximum)
	}
	if got.Resources.ListenBacklogMaximum != 4096 {
		t.Errorf("somaxconn = %d, want 4096", got.Resources.ListenBacklogMaximum)
	}
}

// Containers and hardened kernels hide most of these paths. A missing ceiling
// must leave the field at zero, which analysis reads as "no limit known", not
// as a limit of zero.
func TestCollectToleratesAbsentSocketCeilings(t *testing.T) {
	c := &Collector{ProcRoot: "/proc", readFile: func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "file-nr") {
			return []byte("100 0 1000\n"), nil
		}
		return nil, os.ErrPermission
	}}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Resources == nil {
		t.Fatal("expected the readable gauge to survive")
	}
	if got.Resources.TimeWaitMaximum != 0 || got.Resources.OrphanMaximum != 0 || got.Resources.ListenBacklogMaximum != 0 {
		t.Fatalf("absent ceilings invented values: %+v", got.Resources)
	}
}
