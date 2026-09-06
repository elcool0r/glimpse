package systemd

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestParseFailedUnits(t *testing.T) {
	input := `  UNIT                 LOAD   ACTIVE SUB    DESCRIPTION
  foo.service          loaded failed failed Foo service
  zed.mount            loaded failed failed Zed mount

2 loaded units listed.`
	if got, want := ParseFailedUnits(input), []string{"foo.service", "zed.mount"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestUnavailableSystemctlIsNotAnError(t *testing.T) {
	c := New()
	c.lookPath = func(string) (string, error) { return "", errors.New("missing") }
	data, err := c.Collect(context.Background())
	if err != nil || data.Systemd == nil || data.Systemd.Available {
		t.Fatalf("data=%#v err=%v", data, err)
	}
}
