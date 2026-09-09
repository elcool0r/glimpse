package gatewayping

import (
	"context"
	"errors"
	"testing"
)

const routeTable = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
	"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
	"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"

const pingOutput = `PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.20 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=1.40 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 2 received, 33.3% packet loss, time 2003ms
rtt min/avg/max/mdev = 1.200/1.300/1.400/0.100 ms
`

func fakeReadFile(content string, err error) func(string) ([]byte, error) {
	return func(string) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		return []byte(content), nil
	}
}

func TestDefaultGatewayParsesRouteTable(t *testing.T) {
	// 0101A8C0 little-endian is 192.168.1.1.
	if got := defaultGateway(routeTable); got != "192.168.1.1" {
		t.Fatalf("defaultGateway = %q, want 192.168.1.1", got)
	}
}

func TestDefaultGatewayEmptyWithoutGatewayRoute(t *testing.T) {
	table := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	if got := defaultGateway(table); got != "" {
		t.Fatalf("defaultGateway = %q, want empty", got)
	}
}

func TestDefaultGatewayRequiresUsableZeroMaskRoute(t *testing.T) {
	table := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		// A split default must not be mistaken for the full default route.
		"tun0\t00000000\t0101A8C0\t0003\t0\t0\t1\t00000080\t0\t0\t0\n" +
		// A route that is not UP and an all-zero gateway are unusable too.
		"eth1\t00000000\t0201A8C0\t0002\t0\t0\t1\t00000000\t0\t0\t0\n" +
		"eth2\t00000000\t00000000\t0003\t0\t0\t1\t00000000\t0\t0\t0\n"
	if got := defaultGateway(table); got != "" {
		t.Fatalf("defaultGateway = %q, want empty", got)
	}
}

func TestDefaultGatewaySelectsLowestMetricAndKeepsEqualMetricOrder(t *testing.T) {
	table := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth-backup\t00000000\t0201A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n" +
		"eth-primary\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth-equal\t00000000\t0301A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	if got := defaultGateway(table); got != "192.168.1.1" {
		t.Fatalf("defaultGateway = %q, want lowest metric first route", got)
	}
}

func TestDefaultGatewaySkipsIncompleteOrMalformedRoutes(t *testing.T) {
	table := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\tnot-a-number\t00000000\t0\t0\t0\n" +
		"eth1\t00000000\t0101A8C0\t0003\t0\t0\t100\n"
	if got := defaultGateway(table); got != "" {
		t.Fatalf("defaultGateway = %q, want empty", got)
	}
}

func TestCollectSkipsWithoutDefaultGateway(t *testing.T) {
	c := &Collector{
		readFile: fakeReadFile("Iface\tDestination\tGateway\tFlags\n", nil),
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("ping should not run without a default gateway")
			return nil, nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.GatewayCheck != nil {
		t.Fatalf("expected no gateway check, got %+v", data.GatewayCheck)
	}
}

func TestCollectReportsPacketLoss(t *testing.T) {
	c := &Collector{
		readFile: fakeReadFile(routeTable, nil),
		lookPath: func(string) (string, error) { return "/bin/ping", nil },
		run: func(_ context.Context, path string, args ...string) ([]byte, error) {
			gateway := args[len(args)-1]
			if gateway != "192.168.1.1" {
				t.Fatalf("unexpected gateway %q", gateway)
			}
			// ping exits 1 on any packet loss; the output must still be trusted.
			return []byte(pingOutput), errors.New("exit status 1")
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	check := data.GatewayCheck
	if check == nil || !check.Available {
		t.Fatalf("expected an available gateway check, got %+v", check)
	}
	if check.Sent != 3 || check.Received != 2 {
		t.Fatalf("sent/received = %d/%d, want 3/2", check.Sent, check.Received)
	}
	wantLoss := 100.0 / 3
	if diff := check.PacketLossPct - wantLoss; diff > 0.01 || diff < -0.01 {
		t.Fatalf("packet loss = %.2f, want %.2f", check.PacketLossPct, wantLoss)
	}
	if check.AvgLatencyMillis != 1.3 {
		t.Fatalf("avg latency = %v, want 1.3ms", check.AvgLatencyMillis)
	}
}

func TestCollectReportsUnavailableWhenPingMissing(t *testing.T) {
	c := &Collector{
		readFile: fakeReadFile(routeTable, nil),
		lookPath: func(string) (string, error) { return "", errors.New("executable file not found in $PATH") },
		run: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("run should not be called when ping is missing")
			return nil, nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if data.GatewayCheck != nil {
		t.Fatalf("expected no gateway check when ping is missing, got %+v", data.GatewayCheck)
	}
	if len(data.Diagnostics) != 1 || data.Diagnostics[0].Status != "unavailable" {
		t.Fatalf("expected an unavailable diagnostic, got %+v", data.Diagnostics)
	}
}

func TestNameIsGatewayPing(t *testing.T) {
	if (&Collector{}).Name() != "gateway-ping" {
		t.Fatalf("unexpected name: %s", (&Collector{}).Name())
	}
}
