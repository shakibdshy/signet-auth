package signet_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/shakibdshy/signet"
)

func stateFromURL(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return parsed.Query().Get("state")
}

func oauthCallbackClient(t *testing.T, provider signet.OAuthProvider) (*signet.Client, *memoryStore) {
	t.Helper()
	store := newMemoryStore()
	cfg := testConfig()
	cfg.Store = store
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.OAuth = &signet.OAuthConfig{
		Providers:        []signet.OAuthProvider{provider},
		RedirectBaseURL:  "https://app.example.com",
		AllowedRedirects: []string{"https://app.example.com/dashboard"},
		StateKey:         make([]byte, 32),
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, store
}

func startOAuth(t *testing.T, client *signet.Client) string {
	t.Helper()
	result, err := client.OAuthStart(context.Background(), signet.OAuthStartInput{
		Provider: "google", Redirect: "https://app.example.com/dashboard",
	})
	if err != nil {
		t.Fatalf("OAuthStart: %v", err)
	}
	return stateFromURL(t, result.URL)
}

func TestOAuthCallbackCreatesUserWithVerifiedEmail(t *testing.T) {
	client, store := oauthCallbackClient(t, fakeOAuthProvider{name: "google"})
	state := startOAuth(t, client)
	result, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: state})
	if err != nil || result.User == nil {
		t.Fatalf("OAuthCallback = (%v, %v)", result, err)
	}
	if !result.User.EmailVerified || result.User.Email != "user@example.com" {
		t.Errorf("User = %+v, want verified email", result.User)
	}
	accounts, err := store.AccountsForUser(context.Background(), result.User.ID)
	if err != nil || len(accounts) != 1 || accounts[0].Provider != "google" || accounts[0].PasswordHash != "" {
		t.Fatalf("Accounts = (%v, %v), want one provider Account", accounts, err)
	}
	if len(store.sessions) != 1 {
		t.Errorf("sessions = %d, want 1", len(store.sessions))
	}
}

func TestOAuthCallbackAutoLinksExistingUser(t *testing.T) {
	client, store := oauthCallbackClient(t, fakeOAuthProvider{name: "google"})
	existing, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	state := startOAuth(t, client)
	result, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: state})
	if err != nil || result.User == nil || result.User.ID != existing.User.ID {
		t.Fatalf("OAuthCallback = (%v, %v), want the existing User", result, err)
	}
	accounts, _ := store.AccountsForUser(context.Background(), existing.User.ID)
	if len(accounts) != 2 {
		t.Errorf("Accounts = %d, want credential and provider Accounts", len(accounts))
	}
}

func TestOAuthCallbackRequiresExplicitLinkForUnverifiedEmail(t *testing.T) {
	provider := fakeOAuthProvider{name: "google", identity: &signet.OAuthIdentity{
		Provider: "google", ProviderUserID: "provider-user",
		Email: "unverified@example.com", EmailVerified: false,
	}}
	client, store := oauthCallbackClient(t, provider)
	state := startOAuth(t, client)
	result, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: state})
	if err != nil || result.User != nil || result.LinkToken == "" {
		t.Fatalf("OAuthCallback = (%v, %v), want a link token and no User", result, err)
	}
	if len(store.users) != 0 {
		t.Errorf("users = %d, want none for an unverified email", len(store.users))
	}
	user, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "owner@example.com", Password: "password123"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := client.LinkOAuthAccount(context.Background(), signet.LinkOAuthAccountInput{
		UserID: user.User.ID, LinkToken: result.LinkToken,
	}); err != nil {
		t.Fatalf("LinkOAuthAccount: %v", err)
	}
	if err := client.LinkOAuthAccount(context.Background(), signet.LinkOAuthAccountInput{
		UserID: user.User.ID, LinkToken: result.LinkToken,
	}); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("replayed link token error = %v, want ErrTokenInvalid", err)
	}
}

func TestOAuthCallbackRejectsTamperedState(t *testing.T) {
	client, _ := oauthCallbackClient(t, fakeOAuthProvider{name: "google"})
	_, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: "tampered"})
	if !errors.Is(err, signet.ErrOAuthInvalidState) {
		t.Fatalf("OAuthCallback error = %v, want ErrOAuthInvalidState", err)
	}
}

func TestOAuthCallbackHTTPRedirectsWithSession(t *testing.T) {
	client, _ := oauthCallbackClient(t, fakeOAuthProvider{name: "google"})
	state := startOAuth(t, client)
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=code&state="+url.QueryEscape(state), nil)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "https://app.example.com/dashboard" {
		t.Errorf("Location = %q", rec.Header().Get("Location"))
	}
	if len(rec.Result().Cookies()) != 1 {
		t.Error("expected a session cookie")
	}
}

func TestOAuthCallbackRateLimited(t *testing.T) {
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: false}
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
	_, err = client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: "state"})
	if !errors.Is(err, signet.ErrRateLimited) {
		t.Fatalf("OAuthCallback error = %v, want ErrRateLimited", err)
	}
}
