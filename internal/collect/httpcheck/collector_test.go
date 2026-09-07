package httpcheck

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCollectBothSucceed(t *testing.T) {
	c := &Collector{
		get: func(_ context.Context, url string) (int, time.Duration, error) {
			return 200, 10 * time.Millisecond, nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	check := data.HTTPCheck
	if check == nil || !check.Available {
		t.Fatalf("expected an available check, got %+v", check)
	}
	if check.HTTP == nil || !check.HTTP.Succeeded || check.HTTP.StatusCode != 200 {
		t.Fatalf("unexpected http result: %+v", check.HTTP)
	}
	if check.HTTPS == nil || !check.HTTPS.Succeeded || check.HTTPS.StatusCode != 200 {
		t.Fatalf("unexpected https result: %+v", check.HTTPS)
	}
	if check.HTTP.URL != "http://example.com/" || check.HTTPS.URL != "https://example.com/" {
		t.Fatalf("unexpected urls: http=%q https=%q", check.HTTP.URL, check.HTTPS.URL)
	}
}

func TestCollectHTTPSFailsHTTPSucceeds(t *testing.T) {
	c := &Collector{
		get: func(_ context.Context, url string) (int, time.Duration, error) {
			if url == "https://example.com/" {
				return 0, 0, errors.New("tls: handshake failure")
			}
			return 200, time.Millisecond, nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	check := data.HTTPCheck
	if !check.HTTP.Succeeded {
		t.Fatalf("expected http to succeed: %+v", check.HTTP)
	}
	if check.HTTPS.Succeeded || check.HTTPS.Error == "" {
		t.Fatalf("expected https to fail with a recorded error: %+v", check.HTTPS)
	}
}

func TestCollectBothFail(t *testing.T) {
	c := &Collector{
		get: func(context.Context, string) (int, time.Duration, error) {
			return 0, 0, errors.New("dial tcp: i/o timeout")
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	check := data.HTTPCheck
	if check.HTTP.Succeeded || check.HTTPS.Succeeded {
		t.Fatalf("expected both to fail: %+v", check)
	}
}

func TestNameIsHTTPCheck(t *testing.T) {
	if (&Collector{}).Name() != "http-check" {
		t.Fatalf("unexpected name: %s", (&Collector{}).Name())
	}
}

func TestCollectRecordsProxyUsePerProtocol(t *testing.T) {
	proxyURL, err := url.Parse("http://proxy.internal:3128")
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{
		get: func(_ context.Context, _ string) (int, time.Duration, error) { return 200, time.Millisecond, nil },
		proxy: func(req *http.Request) (*url.URL, error) {
			if req.URL.Scheme == "https" {
				return proxyURL, nil
			}
			return nil, nil
		},
	}
	data, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data.HTTPCheck.HTTP.ProxyUsed || !data.HTTPCheck.HTTPS.ProxyUsed {
		t.Fatalf("proxy use = http:%t https:%t", data.HTTPCheck.HTTP.ProxyUsed, data.HTTPCheck.HTTPS.ProxyUsed)
	}
}

func TestNoProxyDisablesProxySelection(t *testing.T) {
	c := New(true)
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := c.proxyFor(req)
	if err != nil || proxyURL != nil {
		t.Fatalf("--no-proxy selected proxy %v, err=%v", proxyURL, err)
	}
}

func TestDoGetUsesSelectedProxy(t *testing.T) {
	used := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		used = true
		if r.URL.String() != "http://example.com/" {
			t.Errorf("proxy request URL = %q", r.URL.String())
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{proxy: func(*http.Request) (*url.URL, error) { return proxyURL, nil }}
	status, _, err := c.doGet(context.Background(), "http://example.com/")
	if err != nil || status != http.StatusNoContent || !used {
		t.Fatalf("status=%d used=%t err=%v", status, used, err)
	}
}

// ProxyFromEnvironment caches its configuration process-wide. Run these in a
// helper process so the test verifies the real HTTP_PROXY/HTTPS_PROXY/NO_PROXY
// behavior without contaminating other tests.
func TestProxyFromEnvironmentHonorsHTTPHTTPSAndNoProxy(t *testing.T) {
	for _, tt := range []struct {
		name, requestURL, noProxy string
		lowercase                 bool
		wantProxy                 bool
	}{
		{"http", "http://service.example/", "", false, true},
		{"https", "https://service.example/", "", false, true},
		{"lowercase", "https://service.example/", "", true, true},
		{"no-proxy", "https://service.example/", "service.example", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestProxyFromEnvironmentHelper$")
			environment := append(cleanProxyEnvironment(os.Environ()),
				"GLIMPSE_PROXY_HELPER=1",
				"GLIMPSE_PROXY_REQUEST_URL="+tt.requestURL,
				"GLIMPSE_PROXY_WANT="+map[bool]string{true: "used", false: "direct"}[tt.wantProxy],
				"NO_PROXY="+tt.noProxy,
			)
			if tt.lowercase {
				environment = append(environment, "http_proxy=http://proxy.example:3128", "https_proxy=http://secure-proxy.example:8443")
			} else {
				environment = append(environment, "HTTP_PROXY=http://proxy.example:3128", "HTTPS_PROXY=http://secure-proxy.example:8443")
			}
			command.Env = environment
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("proxy helper failed: %v\n%s", err, output)
			}
		})
	}
}

func TestProxyFromEnvironmentHelper(t *testing.T) {
	if os.Getenv("GLIMPSE_PROXY_HELPER") != "1" {
		return
	}
	req, err := http.NewRequest(http.MethodGet, os.Getenv("GLIMPSE_PROXY_REQUEST_URL"), nil)
	if err != nil {
		os.Exit(2)
	}
	proxyURL, err := http.ProxyFromEnvironment(req)
	if err != nil {
		os.Exit(3)
	}
	wantProxy := os.Getenv("GLIMPSE_PROXY_WANT") == "used"
	if (proxyURL != nil) != wantProxy {
		os.Exit(4)
	}
	os.Exit(0)
}

func cleanProxyEnvironment(environment []string) []string {
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		key := strings.ToLower(strings.SplitN(entry, "=", 2)[0])
		switch key {
		case "http_proxy", "https_proxy", "no_proxy", "all_proxy":
			continue
		}
		result = append(result, entry)
	}
	return result
}
