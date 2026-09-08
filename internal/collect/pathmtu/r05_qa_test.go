package pathmtu

import (
	"context"
	"errors"
	"testing"
)

func TestCollectRetainsFeedbackWhenNoTestedDFSizeReplies(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if !containsFlag(args, "-M") {
				return []byte(baselineOKOutput), nil
			}
			return packetTooBigOutput(), errors.New("exit status 1")
		},
	}

	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	check := data.PathMTUCheck
	if check == nil || check.DiscoveredMTU != 0 || !check.PacketTooBigFeedback {
		t.Fatalf("no-reply feedback observation = %+v", check)
	}
}
