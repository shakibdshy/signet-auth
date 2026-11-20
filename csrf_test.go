package signet_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
)

func issueCSRFToken(t *testing.T, client *signet.Client) (string, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/csrf-token", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("csrf-token status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Token == "" {
		t.Fatalf("csrf-token response = %s", rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("csrf cookies = %d, want 1", len(cookies))
	}
	return response.Token, cookies[0]
}

func csrfRequest(client *signet.Client, cookie, csrfCookie *http.Cookie, origin, fetchSite, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/signout", strings.NewReader(`{"session_token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	if csrfCookie != nil {
		req.AddCookie(csrfCookie)
	}
	if token != "" {
		req.Header.Set("X-CSRF-Token", token)
	}
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
	rec := csrfRequest(client, cookie, nil, "https://evil.example", "", "")
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
	rec := csrfRequest(client, cookie, nil, "", "cross-site", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
}

func TestCSRFAllowsSameOriginWithToken(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	token, csrfCookie := issueCSRFToken(t, client)
	for name, tc := range map[string]struct{ origin, site string }{
		"no headers":  {},
		"same origin": {"http://example.com", "same-origin"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := csrfRequest(client, cookie, csrfCookie, tc.origin, tc.site, token)
			if rec.Code != http.StatusNoContent {
				t.Errorf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCSRFRejectsMissingAndTamperedTokens(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	if rec := csrfRequest(client, cookie, nil, "", "", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("missing token status = %d, want 403", rec.Code)
	}
	if rec := csrfRequest(client, cookie, nil, "", "", "tampered"); rec.Code != http.StatusForbidden {
		t.Fatalf("tampered token status = %d, want 403", rec.Code)
	}
}

func TestCSRFTokenExpires(t *testing.T) {
	clock := &adjustableClock{at: testTime}
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.Clock = clock
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	token, csrfCookie := issueCSRFToken(t, client)
	clock.at = testTime.Add(13 * time.Hour)
	if rec := csrfRequest(client, cookie, csrfCookie, "", "", token); rec.Code != http.StatusForbidden {
		t.Fatalf("expired token status = %d, want 403", rec.Code)
	}
}

func TestCSRFDoesNotLogTokens(t *testing.T) {
	var logs bytes.Buffer
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	token, csrfCookie := issueCSRFToken(t, client)
	csrfRequest(client, cookie, csrfCookie, "", "", token)
	if strings.Contains(logs.String(), token) {
		t.Errorf("logs leaked the CSRF token: %q", logs.String())
	}
}

func TestCSRFRejectionEventHasNoToken(t *testing.T) {
	var logs bytes.Buffer
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	token, csrfCookie := issueCSRFToken(t, client)
	rec := csrfRequest(client, cookie, csrfCookie, "https://evil.example", "", token)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	output := logs.String()
	if !strings.Contains(output, "csrf_rejected") {
		t.Errorf("logs = %q, want a csrf_rejected event", output)
	}
	if strings.Contains(output, token) {
		t.Errorf("logs leaked the CSRF token: %q", output)
	}
}

func TestOldCSRFTokenCannotBeReplayedAfterRefresh(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	firstToken, _ := issueCSRFToken(t, client)
	secondToken, secondCookie := issueCSRFToken(t, client)
	if firstToken == secondToken {
		t.Fatal("token refresh produced the same token")
	}
	if rec := csrfRequest(client, cookie, secondCookie, "", "", firstToken); rec.Code != http.StatusForbidden {
		t.Fatalf("old token status = %d, want 403", rec.Code)
	}
	if rec := csrfRequest(client, cookie, secondCookie, "", "", secondToken); rec.Code != http.StatusNoContent {
		t.Fatalf("current token status = %d, want 204", rec.Code)
	}
}

func TestCSRFTokenInSignInResponse(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec, _ := signInOverHTTP(t, client)
	if !strings.Contains(rec.Body.String(), "csrf_token") {
		t.Errorf("sign-in body = %s, want csrf_token", rec.Body.String())
	}
	if len(rec.Result().Cookies()) != 2 {
		t.Errorf("cookies = %d, want session and CSRF cookies", len(rec.Result().Cookies()))
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
	cfg := testConfig()
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
	if rec := csrfRequest(client, cookie, nil, "https://evil.example", "", ""); rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 with CSRF disabled", rec.Code)
	}
	if !strings.Contains(logs.String(), "csrf") {
		t.Errorf("logs = %q, want a warning about disabled CSRF", logs.String())
	}
}
