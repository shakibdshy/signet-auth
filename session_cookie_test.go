package signet_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
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
	cookie := findCookie(cookies, "__Host-signet_session")
	if cookie == nil {
		t.Fatalf("no host session cookie in %+v", cookies)
	}
	if cookie.Name != "__Host-signet_session" || cookie.Value != token {
		t.Errorf("cookie = %s=%s, want the derived host name and the Session token", cookie.Name, cookie.Value)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Errorf("cookie attributes = %+v, want HttpOnly, Secure, SameSite=Lax and Path=/", cookie)
	}
}

func TestSignInUsesPlainNameWithDomain(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
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
	if findCookie(cookies, "signet_session") == nil {
		t.Fatalf("cookies = %+v, want plain name when a Domain is set", cookies)
	}
}

func TestSignOutClearsCookie(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec, token := signInOverHTTP(t, client)
	cookie := findCookie(rec.Result().Cookies(), "__Host-signet_session")
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	req := httptest.NewRequest(http.MethodPost, "/signout", strings.NewReader(`{"session_token":"`+token+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.AddCookie(cookie)
	req.AddCookie(csrfCookie)
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
	clock.At = testTime.Add(31 * time.Minute)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(cookie)
	client.RequireAuth(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an idle-expired Session", rec.Code)
	}
	if len(store.Sessions) != 0 {
		t.Errorf("sessions = %d, want the expired Session revoked", len(store.Sessions))
	}
}

func TestAcceptedRequestExtendsIdleExpiry(t *testing.T) {
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
	var absoluteBefore time.Time
	for _, session := range store.Sessions {
		absoluteBefore = session.AbsoluteExpiresAt
	}
	clock.At = testTime.Add(5 * time.Minute)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(cookie)
	client.RequireAuth(next).ServeHTTP(httptest.NewRecorder(), req)
	var expires, absoluteAfter time.Time
	for _, session := range store.Sessions {
		expires = session.IdleExpiresAt
		absoluteAfter = session.AbsoluteExpiresAt
	}
	want := clock.At.Add(30 * time.Minute)
	if !expires.Equal(want) {
		t.Errorf("idle expiry = %v, want %v", expires, want)
	}
	if !absoluteAfter.Equal(absoluteBefore) {
		t.Errorf("absolute expiry changed from %v to %v", absoluteBefore, absoluteAfter)
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func signInCookie(t *testing.T, client *signet.Client) *http.Cookie {
	t.Helper()
	rec, _ := signInOverHTTP(t, client)
	cookies := rec.Result().Cookies()
	for _, name := range []string{"__Host-signet_session", "signet_session"} {
		if cookie := findCookie(cookies, name); cookie != nil {
			return cookie
		}
	}
	t.Fatalf("no session cookie in %+v", cookies)
	return nil
}
