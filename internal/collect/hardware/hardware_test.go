package hardware

import (
	"context"
	"errors"
	"os"
	"testing"
)

type entry struct {
	name string
	dir  bool
}

func (e entry) Name() string               { return e.name }
func (e entry) IsDir() bool                { return e.dir }
func (e entry) Type() os.FileMode          { return 0 }
func (e entry) Info() (os.FileInfo, error) { return nil, nil }

func TestCollectEDACCounters(t *testing.T) {
	files := map[string]string{
		"/sys/devices/system/edac/mc/mc0/ce_count": "3\n",
		"/sys/devices/system/edac/mc/mc0/ue_count": "0\n",
		"/sys/devices/system/edac/mc/mc0/mc_name":  "Intel MC\n",
	}
	c := &Collector{readDir: func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{entry{"mc0", true}, entry{"not-a-controller", true}}, nil
	}, readFile: func(path string) ([]byte, error) {
		if value, ok := files[path]; ok {
			return []byte(value), nil
		}
		return nil, os.ErrNotExist
	}}
	data, err := c.Collect(context.Background())
	if err != nil || data.Hardware == nil || !data.Hardware.Available || len(data.Hardware.Controllers) != 1 {
		t.Fatalf("data=%+v err=%v", data, err)
	}
	controller := data.Hardware.Controllers[0]
	if controller.Name != "Intel MC" || controller.CorrectableErrors != 3 || controller.UncorrectableErrors != 0 {
		t.Fatalf("controller=%+v", controller)
	}
}

func TestCollectUnavailableEDACIsOptional(t *testing.T) {
	c := &Collector{readDir: func(string) ([]os.DirEntry, error) { return nil, errors.New("not mounted") }}
	data, err := c.Collect(context.Background())
	if err != nil || data.Hardware != nil || len(data.Diagnostics) != 1 || data.Diagnostics[0].Status != "unavailable" {
		t.Fatalf("data=%+v err=%v", data, err)
	}
}
