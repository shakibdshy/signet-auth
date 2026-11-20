package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

func fuzzServiceClient() *signet.Client {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	client, err := signet.New(cfg)
	if err != nil {
		panic(err)
	}
	return client
}

func servePost(handler http.Handler, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func FuzzArgonVerifier(f *testing.F) {
	f.Add("not-a-verifier")
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA")
	hasher := signet.Argon2idHasher{}
	f.Fuzz(func(t *testing.T, encoded string) {
		// Parsing must never panic. Verify is deliberately excluded: a fuzzed
		// but syntactically valid parameter set could request large memory.
		needsRehash := hasher.NeedsRehash(encoded)
		if !strings.HasPrefix(encoded, "$argon2id$") && !needsRehash {
			t.Fatal("malformed verifier was accepted")
		}
	})
}

func FuzzSessionTokenSignOut(f *testing.F) {
	f.Add("")
	f.Add("opaque-session-token")
	client := fuzzServiceClient()
	f.Fuzz(func(t *testing.T, token string) {
		if err := client.SignOut(context.Background(), signet.SignOutInput{SessionToken: token}); err != nil {
			t.Fatalf("SignOut with arbitrary token: %v", err)
		}
	})
}

func FuzzJSONRequestBodies(f *testing.F) {
	f.Add([]byte(`{"email":"user@example.com","password":"password123"}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(nil))
	client := fuzzServiceClient()
	handler := client.Handler()
	f.Fuzz(func(t *testing.T, body []byte) {
		rec := servePost(handler, "/signup", body, map[string]string{"Content-Type": "application/json"})
		if code := rec.Code; code < http.StatusOK || code >= http.StatusInternalServerError {
			t.Fatalf("arbitrary JSON produced server error %d", code)
		}
	})
}

func oauthState(client *signet.Client) string {
	result, err := client.OAuthStart(context.Background(), signet.OAuthStartInput{
		Provider: "google", Redirect: "https://app.example.com/dashboard",
	})
	if err != nil {
		panic(err)
	}
	parsed, err := url.Parse(result.URL)
	if err != nil {
		panic(err)
	}
	return parsed.Query().Get("state")
}

func FuzzOAuthState(f *testing.F) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.OAuth = &signet.OAuthConfig{
		Providers:        []signet.OAuthProvider{fakeOAuthProvider{name: "google"}},
		RedirectBaseURL:  "https://app.example.com",
		AllowedRedirects: []string{"https://app.example.com/dashboard"},
		StateKey:         make([]byte, 32),
	}
	oauthClient, err := signet.New(cfg)
	if err != nil {
		f.Fatalf("New: %v", err)
	}
	f.Add(oauthState(oauthClient))
	f.Add("tampered-state")
	f.Fuzz(func(t *testing.T, state string) {
		_, err := oauthClient.OAuthCallback(context.Background(), signet.OAuthCallbackInput{
			Code: "code", State: state,
		})
		if err != nil && !errors.Is(err, signet.ErrOAuthInvalidState) {
			t.Fatalf("unexpected error for arbitrary state: %v", err)
		}
	})
}

func csrfTokenAndCookie(client *signet.Client) (string, *http.Cookie) {
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/csrf-token", nil))
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		panic(err)
	}
	result := rec.Result()
	if len(result.Cookies()) == 0 {
		panic("csrf-token issued no cookie")
	}
	return response.Token, result.Cookies()[0]
}

func FuzzCSRFToken(f *testing.F) {
	client := fuzzServiceClient()
	validToken, validCookie := csrfTokenAndCookie(client)
	f.Add(validToken)
	f.Add("not-a-csrf-token")
	handler := client.Handler()
	f.Fuzz(func(t *testing.T, token string) {
		req := httptest.NewRequest(http.MethodPost, "/signout", strings.NewReader(`{"session_token":"x"}`))
		// The CSRF cookie must be present; otherwise csrfRejected returns 403
		// before the header value is ever validated.
		//nolint:gosec // G124: deliberately forged cookie for the fuzz target.
		req.AddCookie(&http.Cookie{Name: "__Host-signet_session", Value: "opaque"})
		req.AddCookie(validCookie)
		req.Header.Set("X-CSRF-Token", token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if code := rec.Code; code != http.StatusForbidden && code != http.StatusNoContent {
			t.Fatalf("unexpected status %d for arbitrary CSRF token", code)
		}
	})
}
