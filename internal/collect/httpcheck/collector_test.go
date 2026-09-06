package httpcheck

import (
	"context"
	"errors"
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
