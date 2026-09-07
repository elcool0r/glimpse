package networkstate

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/elcool0r/glimpse/internal/model"
)

func TestParseListeningSockets(t *testing.T) {
	raw := "tcp LISTEN 0 4096 127.0.0.1:53 0.0.0.0:*\nudp UNCONN 0 0 [::]:5353 [::]:*\ntcp LISTEN 0 4096 127.0.0.1:53 0.0.0.0:*\n"
	got := ParseListeningSockets(raw)
	want := []model.ListeningSocket{{Protocol: "tcp", Address: "127.0.0.1", Port: 53}, {Protocol: "udp", Address: "::", Port: 5353}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestBoundedInventoriesReportReducedCoverage(t *testing.T) {
	var sockets strings.Builder
	for i := 0; i <= maxSockets; i++ {
		sockets.WriteString("tcp LISTEN 0 4096 127.0.0.1:")
		sockets.WriteString(strconv.Itoa(10000 + i))
		sockets.WriteString(" 0.0.0.0:*\n")
	}
	listeners, listenersLimited := parseListeningSocketsBounded(sockets.String())
	if len(listeners) != maxSockets || !listenersLimited {
		t.Fatalf("listeners=%d limited=%v", len(listeners), listenersLimited)
	}

	var routes strings.Builder
	for i := 0; i <= maxRoutes; i++ {
		routes.WriteString("192.0.2.")
		routes.WriteString(strconv.Itoa(i))
		routes.WriteString("/32 dev eth0\n")
	}
	parsedRoutes, routesLimited := parseRoutesBounded(routes.String())
	if len(parsedRoutes) != maxRoutes || !routesLimited {
		t.Fatalf("routes=%d limited=%v", len(parsedRoutes), routesLimited)
	}
}

func TestParseConnectionStates(t *testing.T) {
	got := ParseConnectionStates("ESTAB 0 0 a:1 b:2\ntcp LISTEN 0 1 *:22 *:*\nESTAB 0 0 a:3 b:4\n")
	want := []model.ConnectionState{{State: "ESTAB", Count: 2}, {State: "LISTEN", Count: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestParseRoutes(t *testing.T) {
	got := ParseRoutes("default via 192.0.2.1 dev eth0 proto dhcp metric 100\n192.0.2.0/24 dev eth0 proto kernel scope link src 192.0.2.2\n")
	if len(got) != 2 || got[0].Gateway != "192.0.2.1" || got[0].Device != "eth0" || got[0].Metric == nil || *got[0].Metric != 100 || got[1].Destination != "192.0.2.0/24" {
		t.Fatalf("routes=%+v", got)
	}
}
