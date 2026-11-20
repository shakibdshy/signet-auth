package signet_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
)

func signInOverHTTP(t *testing.T, client *signet.Client) (*httptest.ResponseRecorder, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(`{"email":"user@example.com","password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign-in status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode sign-in: %v", err)
	}
	return rec, response.SessionToken
}

func TestSignInSetsSecureHostCookie(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec, token := signInOverHTTP(t, client)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != "__Host-signet_session" || cookie.Value != token {
		t.Errorf("cookie = %s=%s, want the derived host name and the Session token", cookie.Name, cookie.Value)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Errorf("cookie attributes = %+v, want HttpOnly, Secure, SameSite=Lax and Path=/", cookie)
	}
}

func TestSignInUsesPlainNameWithDomain(t *testing.T) {
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.Cookie.Domain = "example.com"
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec, _ := signInOverHTTP(t, client)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "signet_session" {
		t.Fatalf("cookies = %+v, want plain name when a Domain is set", cookies)
	}
}

func TestSignOutClearsCookie(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec, token := signInOverHTTP(t, client)
	cookie := rec.Result().Cookies()[0]
	req := httptest.NewRequest(http.MethodPost, "/signout", strings.NewReader(`{"session_token":"`+token+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	client.Handler().ServeHTTP(out, req)
	if out.Code != http.StatusNoContent {
		t.Fatalf("sign-out status = %d, body = %s", out.Code, out.Body.String())
	}
	cleared := out.Result().Cookies()[0]
	if cleared.MaxAge >= 0 || cleared.Value != "" {
		t.Errorf("cleared cookie = %+v, want MaxAge < 0 and empty value", cleared)
	}
}

func TestRequireAuthAndUserFromContext(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	protected := client.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := signet.UserFromContext(r.Context())
		if !ok || user.Email != "user@example.com" {
			t.Errorf("UserFromContext = (%v, %v)", user, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestRequireAuthRejectsAnonymousAndOptionalAuthPasses(t *testing.T) {
	client, _, _ := newAuthClient()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	rec := httptest.NewRecorder()
	client.RequireAuth(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/private", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("RequireAuth status = %d, want 401", rec.Code)
	}
	rec = httptest.NewRecorder()
	client.OptionalAuth(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/public", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("OptionalAuth status = %d, want 204", rec.Code)
	}
}

func TestExpiredSessionIsRejectedAndRevoked(t *testing.T) {
	clock := &adjustableClock{at: testTime}
	store := newMemoryStore()
	cfg := testConfig()
	cfg.Store = store
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
	clock.at = testTime.Add(31 * time.Minute)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(cookie)
	client.RequireAuth(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an idle-expired Session", rec.Code)
	}
	if len(store.sessions) != 0 {
		t.Errorf("sessions = %d, want the expired Session revoked", len(store.sessions))
	}
}

func TestAcceptedRequestExtendsIdleExpiry(t *testing.T) {
	clock := &adjustableClock{at: testTime}
	store := newMemoryStore()
	cfg := testConfig()
	cfg.Store = store
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
	var absoluteBefore time.Time
	for _, session := range store.sessions {
		absoluteBefore = session.AbsoluteExpiresAt
	}
	clock.at = testTime.Add(5 * time.Minute)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(cookie)
	client.RequireAuth(next).ServeHTTP(httptest.NewRecorder(), req)
	var expires, absoluteAfter time.Time
	for _, session := range store.sessions {
		expires = session.IdleExpiresAt
		absoluteAfter = session.AbsoluteExpiresAt
	}
	want := clock.at.Add(30 * time.Minute)
	if !expires.Equal(want) {
		t.Errorf("idle expiry = %v, want %v", expires, want)
	}
	if !absoluteAfter.Equal(absoluteBefore) {
		t.Errorf("absolute expiry changed from %v to %v", absoluteBefore, absoluteAfter)
	}
}

func signInCookie(t *testing.T, client *signet.Client) *http.Cookie {
	t.Helper()
	rec, _ := signInOverHTTP(t, client)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	return cookies[0]
}
