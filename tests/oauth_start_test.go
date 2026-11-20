package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

func oauthStartClient(t *testing.T, limiter *testutil.Limiter) *signet.Client {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = limiter
	cfg.OAuth = &signet.OAuthConfig{
		Providers:        []signet.OAuthProvider{fakeOAuthProvider{name: "google"}},
		RedirectBaseURL:  "https://app.example.com",
		AllowedRedirects: []string{"https://app.example.com/dashboard"},
		StateKey:         make([]byte, 32),
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestOAuthDisabledByDefault(t *testing.T) {
	client, _, _ := newAuthClient()
	_, err := client.OAuthStart(context.Background(), signet.OAuthStartInput{Provider: "google", Redirect: "https://app.example.com/dashboard"})
	if !errors.Is(err, signet.ErrOAuthDisabled) {
		t.Fatalf("OAuthStart error = %v, want ErrOAuthDisabled", err)
	}
}

func TestOAuthStartValidatesRequest(t *testing.T) {
	client := oauthStartClient(t, &testutil.Limiter{Allowed: true})
	tests := []struct {
		name string
		in   signet.OAuthStartInput
		want error
	}{
		{"unknown provider", signet.OAuthStartInput{Provider: "unknown", Redirect: "https://app.example.com/dashboard"}, signet.ErrOAuthProviderNotFound},
		{"disallowed redirect", signet.OAuthStartInput{Provider: "google", Redirect: "https://evil.example"}, signet.ErrOAuthRedirectNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := client.OAuthStart(context.Background(), tt.in); !errors.Is(err, tt.want) {
				t.Fatalf("OAuthStart error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestOAuthStartReturnsPKCEAndState(t *testing.T) {
	client := oauthStartClient(t, &testutil.Limiter{Allowed: true})
	result, err := client.OAuthStart(context.Background(), signet.OAuthStartInput{Provider: "google", Redirect: "https://app.example.com/dashboard"})
	if err != nil {
		t.Fatalf("OAuthStart: %v", err)
	}
	for _, part := range []string{"state=", "code_challenge=", "code_challenge_method=S256"} {
		if !strings.Contains(result.URL, part) {
			t.Errorf("URL = %q, want %q", result.URL, part)
		}
	}
	if !strings.Contains(result.URL, "client-id") {
		t.Errorf("URL = %q, want the client id", result.URL)
	}
}

func TestOAuthStartHTTP(t *testing.T) {
	client := oauthStartClient(t, &testutil.Limiter{Allowed: true})
	req := httptest.NewRequest(http.MethodPost, "/oauth/start", strings.NewReader(`{"provider":"google","redirect":"https://app.example.com/dashboard"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "url") {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestOAuthStartRateLimited(t *testing.T) {
	client := oauthStartClient(t, &testutil.Limiter{Allowed: false})
	req := httptest.NewRequest(http.MethodPost, "/oauth/start", strings.NewReader(`{"provider":"google","redirect":"https://app.example.com/dashboard"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body = %s", rec.Code, rec.Body.String())
	}
}
