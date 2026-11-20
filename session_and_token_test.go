package signet_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/secret"
	"github.com/shakibdshy/signet/internal/testutil"
)

func TestAbsoluteExpiryRejectsAndRevokes(t *testing.T) {
	clock := &testutil.Clock{At: testTime}
	store := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Clock = clock
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	for _, session := range store.Sessions {
		session.AbsoluteExpiresAt = testTime.Add(time.Minute)
	}
	clock.At = testTime.Add(2 * time.Minute)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	client.RequireAuth(next).ServeHTTP(rec, req)
	if called || rec.Code != http.StatusUnauthorized {
		t.Errorf("called = %v, status = %d; want false and 401", called, rec.Code)
	}
	if len(store.Sessions) != 0 {
		t.Errorf("sessions = %d, want the expired Session revoked", len(store.Sessions))
	}
}

func TestTamperedSessionCookieIsRejected(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	//nolint:gosec // G124: deliberately forged cookie used to prove rejection.
	req.AddCookie(&http.Cookie{Name: "__Host-signet_session", Value: "not-a-real-session-token"})
	rec := httptest.NewRecorder()
	client.RequireAuth(next).ServeHTTP(rec, req)
	if called || rec.Code != http.StatusUnauthorized {
		t.Errorf("called = %v, status = %d; want false and 401", called, rec.Code)
	}
}

func TestMiddlewareDoesNotLogSessionToken(t *testing.T) {
	var logs bytes.Buffer
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec, token := signInOverHTTP(t, client)
	cookie := rec.Result().Cookies()[0]
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(cookie)
	client.RequireAuth(next).ServeHTTP(httptest.NewRecorder(), req)
	if strings.Contains(logs.String(), token) {
		t.Errorf("logs leaked the Session token: %q", logs.String())
	}
}

func TestTokenEndpointIsRateLimited(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: false}
	cfg.JWT = &signet.JWTConfig{Algorithm: "HS256", Key: testJWTKey}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"email":"user@example.com","password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body = %s", rec.Code, rec.Body.String())
	}
}

func TestSecretDigestIsFixedWidth(t *testing.T) {
	got := secret.Digest("")
	if len(got) != 64 {
		t.Fatalf("digest length = %d, want 64 hex chars", len(got))
	}
}
