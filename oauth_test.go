package signet_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/shakibdshy/signet"
)

type fakeOAuthProvider struct {
	name         string
	identity     *signet.OAuthIdentity
	seenVerifier *string
}

func (p fakeOAuthProvider) Name() string { return p.name }
func (p fakeOAuthProvider) AuthURL(clientID, redirectURI, state, challenge string) string {
	if clientID == "" {
		clientID = "client-id"
	}
	query := url.Values{}
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	return "https://provider.example/authorize?" + query.Encode()
}
func (p fakeOAuthProvider) Exchange(_ context.Context, _, verifier, _ string) (*signet.OAuthIdentity, error) {
	if p.seenVerifier != nil {
		*p.seenVerifier = verifier
	}
	if p.identity != nil {
		return p.identity, nil
	}
	return &signet.OAuthIdentity{
		Provider: p.name, ProviderUserID: "provider-user",
		Email: "user@example.com", EmailVerified: true,
	}, nil
}

var _ signet.OAuthProvider = fakeOAuthProvider{}

func TestNewValidatesOAuthConfig(t *testing.T) {
	tests := []struct {
		name  string
		oauth *signet.OAuthConfig
		want  error
	}{
		{"no providers", &signet.OAuthConfig{StateKey: make([]byte, 32)}, signet.ErrInvalidOAuthConfig},
		{"short state key", &signet.OAuthConfig{Providers: []signet.OAuthProvider{fakeOAuthProvider{name: "google"}}, StateKey: make([]byte, 16)}, signet.ErrInvalidOAuthConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Store = newMemoryStore()
			cfg.Mailer = fakeMailer{}
			cfg.RateLimiter = &recordingLimiter{allow: true}
			cfg.OAuth = tt.oauth
			if _, err := signet.New(cfg); !errors.Is(err, tt.want) {
				t.Fatalf("New error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestOAuthConfigAcceptsValidSetup(t *testing.T) {
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.OAuth = &signet.OAuthConfig{
		Providers:        []signet.OAuthProvider{fakeOAuthProvider{name: "google"}},
		RedirectBaseURL:  "https://app.example.com",
		AllowedRedirects: []string{"https://app.example.com/dashboard"},
		StateKey:         make([]byte, 32),
	}
	if _, err := signet.New(cfg); err != nil {
		t.Fatalf("New error = %v, want nil", err)
	}
}
