package signet_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
)

func csrfRequest(client *signet.Client, cookie *http.Cookie, origin, fetchSite string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/signout", strings.NewReader(`{"session_token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if fetchSite != "" {
		req.Header.Set("Sec-Fetch-Site", fetchSite)
	}
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	return rec
}

func TestCSRFRejectsCrossOriginStateChange(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	rec := csrfRequest(client, cookie, "https://evil.example", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "csrf") {
		t.Errorf("body = %s, want a csrf error code", rec.Body.String())
	}
}

func TestCSRFRejectsCrossSiteFetch(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	rec := csrfRequest(client, cookie, "", "cross-site")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
}

func TestCSRFAllowsSameOriginAndHeaderlessClients(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	for name, tc := range map[string]struct{ origin, site string }{
		"no headers":  {},
		"same origin": {"http://example.com", "same-origin"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := csrfRequest(client, cookie, tc.origin, tc.site)
			if rec.Code != http.StatusNoContent {
				t.Errorf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCSRFGuardCoversProtectedApplicationHandlers(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	called := false
	protected := client.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/private", strings.NewReader("x"))
	req.AddCookie(cookie)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if called || rec.Code != http.StatusForbidden {
		t.Errorf("called = %v, status = %d; want false and 403", called, rec.Code)
	}
}

func TestCSRFDoesNotAffectAnonymousRequests(t *testing.T) {
	client, _, _ := newAuthClient()
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(`{"email":"user@example.com","password":"password123"}`))
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 from sign-in, not 403 from CSRF", rec.Code)
	}
}

func TestCSRFCanBeDisabledExplicitly(t *testing.T) {
	var logs bytes.Buffer
	cfg := signet.DefaultConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.InsecureDisableCSRF = true
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	if rec := csrfRequest(client, cookie, "https://evil.example", ""); rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 with CSRF disabled", rec.Code)
	}
	if !strings.Contains(logs.String(), "csrf") {
		t.Errorf("logs = %q, want a warning about disabled CSRF", logs.String())
	}
}
