package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

func sessionForToken(t *testing.T, store *testutil.Store, raw string) *signet.Session {
	t.Helper()
	sum := sha256.Sum256([]byte(raw))
	digest := hex.EncodeToString(sum[:])
	for _, session := range store.Sessions {
		if session.TokenHash == digest {
			return session
		}
	}
	t.Fatal("session not found")
	return nil
}

func TestFreshSessionWindowDisabledByDefault(t *testing.T) {
	client, store, _ := changePasswordClient(t)
	ctx := context.Background()
	signUp, _ := client.SignUp(ctx, signet.SignUpInput{Email: "fresh@example.com", Password: "correct horse", Name: "Ada"})
	signIn, err := client.SignIn(ctx, signet.SignInInput{Email: "fresh@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	_ = signUp
	if err := client.VerifyFreshSession(ctx, signIn.SessionToken); err != nil {
		t.Fatalf("freshness disabled should pass: %v", err)
	}
	// Touch LastSeenAt to prove it is not used.
	sessionForToken(t, store, signIn.SessionToken).LastSeenAt = time.Now()
	if err := client.VerifyFreshSession(ctx, signIn.SessionToken); err != nil {
		t.Fatalf("freshness disabled after touch: %v", err)
	}
}

func TestFreshSessionUsesCreatedAt(t *testing.T) {
	cfgStore := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = cfgStore
	cfg.Mailer = &testutil.Mailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	window := 5 * time.Minute
	cfg.Session.FreshAge = window
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "fresh@example.com", Password: "correct horse", Name: "Ada"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn, err := client.SignIn(ctx, signet.SignInInput{Email: "fresh@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	session := sessionForToken(t, cfgStore, signIn.SessionToken)
	session.CreatedAt = time.Now().Add(-time.Hour)
	session.LastSeenAt = time.Now() // recent activity must not make it fresh
	if err := client.VerifyFreshSession(ctx, signIn.SessionToken); !errors.Is(err, signet.ErrSessionNotFresh) {
		t.Fatalf("error = %v, want ErrSessionNotFresh", err)
	}
}

func TestFreshSessionMiddleware(t *testing.T) {
	cfgStore := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = cfgStore
	cfg.Mailer = &testutil.Mailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Session.FreshAge = time.Hour
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "fresh@example.com", Password: "correct horse", Name: "Ada"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn, _ := client.SignIn(ctx, signet.SignInInput{Email: "fresh@example.com", Password: "correct horse"})

	var called bool
	handler := client.RequireFreshSession(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	//nolint:gosec // test cookie for middleware assertion
	req.AddCookie(&http.Cookie{Name: "__Host-signet_session", Value: signIn.SessionToken, Secure: true, HttpOnly: true})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("fresh request: called=%v status=%d", called, rec.Code)
	}

	sessionForToken(t, cfgStore, signIn.SessionToken).CreatedAt = time.Now().Add(-2 * time.Hour)
	called = false
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale request: called=%v status=%d", called, rec.Code)
	}
}

func TestFreshSessionMiddlewareRejectsForgedCookieWithDefaultConfig(t *testing.T) {
	client, _, _ := changePasswordClient(t)
	var called bool
	handler := client.RequireFreshSession(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	//nolint:gosec // deliberately forged test cookie
	req.AddCookie(&http.Cookie{Name: "__Host-signet_session", Value: "forged", Secure: true, HttpOnly: true})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("forged cookie: called=%v status=%d", called, rec.Code)
	}
}
