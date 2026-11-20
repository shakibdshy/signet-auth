package signet_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
)

func TestOAuthStateExpires(t *testing.T) {
	clock := &adjustableClock{at: testTime}
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.Clock = clock
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
	result, err := client.OAuthStart(context.Background(), signet.OAuthStartInput{Provider: "google", Redirect: "https://app.example.com/dashboard"})
	if err != nil {
		t.Fatalf("OAuthStart: %v", err)
	}
	state := stateFromURL(t, result.URL)
	clock.at = testTime.Add(11 * time.Minute)
	if _, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: state}); !errors.Is(err, signet.ErrOAuthInvalidState) {
		t.Fatalf("expired state error = %v, want ErrOAuthInvalidState", err)
	}
}

func TestPKCEVerifierIsNotExposedInURL(t *testing.T) {
	client := oauthStartClient(t, &recordingLimiter{allow: true})
	result, err := client.OAuthStart(context.Background(), signet.OAuthStartInput{Provider: "google", Redirect: "https://app.example.com/dashboard"})
	if err != nil {
		t.Fatalf("OAuthStart: %v", err)
	}
	state := stateFromURL(t, result.URL)
	if len(state) < 32 || state == "state-value" {
		t.Errorf("state = %q, want an opaque encrypted value", state)
	}
	if strings.Contains(result.URL, "verifier") || strings.Contains(result.URL, "nonce") {
		t.Errorf("URL leaked flow internals: %q", result.URL)
	}
}

func TestOAuthStateIsSingleUse(t *testing.T) {
	client, _ := oauthCallbackClient(t, fakeOAuthProvider{name: "google"})
	state := startOAuth(t, client)
	if _, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: state}); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	if _, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: state}); !errors.Is(err, signet.ErrOAuthInvalidState) {
		t.Fatalf("replayed state error = %v, want ErrOAuthInvalidState", err)
	}
}

func TestPKCEVerifierReachesProvider(t *testing.T) {
	var verifier string
	provider := fakeOAuthProvider{name: "google", seenVerifier: &verifier}
	client, _ := oauthCallbackClient(t, provider)
	state := startOAuth(t, client)
	if _, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: state}); err != nil {
		t.Fatalf("OAuthCallback: %v", err)
	}
	if verifier == "" {
		t.Error("PKCE verifier was not passed to the provider exchange")
	}
}

func TestOAuthEmailNotVerifiedSentinel(t *testing.T) {
	provider := fakeOAuthProvider{name: "google", identity: &signet.OAuthIdentity{
		Provider: "google", ProviderUserID: "provider-user", Email: "", EmailVerified: true,
	}}
	client, _ := oauthCallbackClient(t, provider)
	state := startOAuth(t, client)
	_, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: state})
	if !errors.Is(err, signet.ErrOAuthEmailNotVerified) {
		t.Fatalf("OAuthCallback error = %v, want ErrOAuthEmailNotVerified", err)
	}
}

func TestOAuthAccountConflictSentinel(t *testing.T) {
	provider := &fakeOAuthProvider{name: "google", identity: &signet.OAuthIdentity{
		Provider: "google", ProviderUserID: "same-provider-user",
		Email: "owner@example.com", EmailVerified: true,
	}}
	client, _ := oauthCallbackClient(t, provider)
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "owner@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignUp owner: %v", err)
	}
	state := startOAuth(t, client)
	if _, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: state}); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "second@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignUp second: %v", err)
	}
	provider.identity = &signet.OAuthIdentity{
		Provider: "google", ProviderUserID: "same-provider-user",
		Email: "second@example.com", EmailVerified: true,
	}
	state = startOAuth(t, client)
	_, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: state})
	if !errors.Is(err, signet.ErrOAuthAccountConflict) {
		t.Fatalf("second callback error = %v, want ErrOAuthAccountConflict", err)
	}
}

func TestLinkTokenExpires(t *testing.T) {
	clock := &adjustableClock{at: testTime}
	provider := fakeOAuthProvider{name: "google", identity: &signet.OAuthIdentity{
		Provider: "google", ProviderUserID: "provider-user",
		Email: "unverified@example.com", EmailVerified: false,
	}}
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.Clock = clock
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
	started, err := client.OAuthStart(context.Background(), signet.OAuthStartInput{Provider: "google", Redirect: "https://app.example.com/dashboard"})
	if err != nil {
		t.Fatalf("OAuthStart: %v", err)
	}
	state := stateFromURL(t, started.URL)
	callback, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code", State: state})
	if err != nil {
		t.Fatalf("OAuthCallback: %v", err)
	}
	user, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "owner@example.com", Password: "password123"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	clock.at = testTime.Add(11 * time.Minute)
	err = client.LinkOAuthAccount(context.Background(), signet.LinkOAuthAccountInput{
		UserID: user.User.ID, LinkToken: callback.LinkToken,
	})
	if !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("expired link token error = %v, want ErrTokenInvalid", err)
	}
}

func TestOAuthDoesNotLogSecrets(t *testing.T) {
	var logs bytes.Buffer
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
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
	started, err := client.OAuthStart(context.Background(), signet.OAuthStartInput{Provider: "google", Redirect: "https://app.example.com/dashboard"})
	if err != nil {
		t.Fatalf("OAuthStart: %v", err)
	}
	state := stateFromURL(t, started.URL)
	if _, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "secret-code", State: state}); err != nil {
		t.Fatalf("OAuthCallback: %v", err)
	}
	output := logs.String()
	if strings.Contains(output, "secret-code") || strings.Contains(output, state) {
		t.Errorf("logs leaked OAuth secrets: %q", output)
	}
}
