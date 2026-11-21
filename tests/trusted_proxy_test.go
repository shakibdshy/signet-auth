package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

type keyLimiter struct{ keys []string }

func (l *keyLimiter) Allow(_ context.Context, key string) (bool, error) {
	l.keys = append(l.keys, key)
	return !strings.Contains(key, "203.0.113.8"), nil
}

func TestTrustedProxyUsesForwardedKey(t *testing.T) {
	store := testutil.NewStore()
	limiter := &keyLimiter{}
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = &testutil.Mailer{}
	cfg.RateLimiter = limiter
	cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(`{"email":"proxy@example.com","password":"correct horse","name":"Ada"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.8")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	found := false
	for _, k := range limiter.keys {
		if strings.Contains(k, "203.0.113.8") {
			found = true
		}
	}
	if !found {
		t.Fatalf("derived key not used: %v", limiter.keys)
	}
}

func TestNoTrustedProxiesIgnoresXFF(t *testing.T) {
	store := testutil.NewStore()
	limiter := &keyLimiter{}
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = &testutil.Mailer{}
	cfg.RateLimiter = limiter
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(`{"email":"proxy2@example.com","password":"correct horse","name":"Ada"}`))
	req.RemoteAddr = "198.51.100.4:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.8")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("xff should be ignored without trusted proxies")
	}
}
