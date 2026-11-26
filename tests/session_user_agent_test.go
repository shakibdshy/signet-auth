package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/shakibdshy/signet-auth"
)

const testUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) SignetTest/1.0"

func signInOverHTTPWithUserAgent(t *testing.T, client *signet.Client, userAgent string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(`{"email":"user@example.com","password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /signin status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	return rec
}

func sessionCookieFromResponse(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, name := range []string{"__Host-signet_session", "signet_session"} {
		if cookie := findCookie(rec.Result().Cookies(), name); cookie != nil {
			return cookie
		}
	}
	t.Fatalf("no session cookie in %+v", rec.Result().Cookies())
	return nil
}

func listSessionsOverHTTP(t *testing.T, client *signet.Client, cookie *http.Cookie) []map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /sessions status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || len(response.Sessions) == 0 {
		t.Fatalf("GET /sessions = %s, want at least one Session", rec.Body.String())
	}
	return response.Sessions
}

func TestSignInRecordsUserAgentOnSession(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec := signInOverHTTPWithUserAgent(t, client, testUserAgent)
	sessions := listSessionsOverHTTP(t, client, sessionCookieFromResponse(t, rec))
	if got, ok := sessions[0]["user_agent"].(string); !ok || got != testUserAgent {
		t.Fatalf("session user_agent = %#v, want %#v", sessions[0]["user_agent"], testUserAgent)
	}
}

func TestSignInRecordsEmptyUserAgentWhenHeaderAbsent(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec := signInOverHTTPWithUserAgent(t, client, "")
	sessions := listSessionsOverHTTP(t, client, sessionCookieFromResponse(t, rec))
	got, ok := sessions[0]["user_agent"].(string)
	if !ok {
		t.Fatalf("session user_agent missing or not a string: %s", rec.Body.String())
	}
	if got != "" {
		t.Fatalf("session user_agent = %#v, want an empty string", got)
	}
}

func TestUserAgentTruncatedToRuneBoundary(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	long := strings.Repeat("→", 400) + strings.Repeat("x", 400) // 800 runes, multibyte prefix
	rec := signInOverHTTPWithUserAgent(t, client, long)
	sessions := listSessionsOverHTTP(t, client, sessionCookieFromResponse(t, rec))
	got, ok := sessions[0]["user_agent"].(string)
	if !ok {
		t.Fatalf("session user_agent missing or not a string: %s", rec.Body.String())
	}
	if !utf8.ValidString(got) {
		t.Fatalf("stored user_agent is not valid UTF-8")
	}
	if gotRuneCount, wantRuneCount := utf8.RuneCountInString(got), 512; gotRuneCount != wantRuneCount {
		t.Fatalf("stored user_agent has %d runes, want %d", gotRuneCount, wantRuneCount)
	}
	if !strings.HasPrefix(long, got) {
		t.Fatalf("stored user_agent is not a prefix of the sent header")
	}
}
