package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
	"github.com/shakibdshy/signet/oauth/oidc"
)

type discoveryServer struct {
	server *httptest.Server
	doc    map[string]any
}

func newDiscoveryServer(t *testing.T, overrides map[string]any) *discoveryServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &discoveryServer{doc: map[string]any{}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(s.doc)
		case "/authorize", "/token", "/userinfo", "/jwks":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	s.server = server
	base := server.URL
	s.doc = map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"userinfo_endpoint":                     base + "/userinfo",
		"jwks_uri":                              base + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	}
	for k, v := range overrides {
		s.doc[k] = v
	}
	_ = key
	return s
}

func (d *discoveryServer) config(providerID string) oidc.Config {
	return oidc.Config{
		ProviderID:   providerID,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Issuer:       d.server.URL,
		HTTPClient:   d.server.Client(),
	}
}

func TestOIDCDiscoverySuccess(t *testing.T) {
	d := newDiscoveryServer(t, nil)
	defer d.server.Close()
	provider, err := oidc.NewProvider(context.Background(), d.config("acme"))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if provider.Name() != "acme" {
		t.Fatalf("name = %q", provider.Name())
	}
	url := provider.AuthURL("", "https://api.example.com/auth/oauth/callback", "state", "challenge")
	if url == "" {
		t.Fatal("empty authorization URL")
	}
}

func TestOIDCDiscoveryFailureFailsConstruction(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()
	_, err := oidc.NewProvider(context.Background(), oidc.Config{
		ProviderID: "acme", ClientID: "client-id", Issuer: server.URL, HTTPClient: server.Client(),
	})
	if err == nil {
		t.Fatal("discovery failure must fail construction")
	}
}

func TestOIDCDiscoveryRejectsHTTPAndRedirect(t *testing.T) {
	// Plain HTTP discovery URL.
	_, err := oidc.NewProvider(context.Background(), oidc.Config{
		ProviderID: "acme", ClientID: "client-id", Issuer: "http://example.com",
	})
	if err == nil {
		t.Fatal("HTTP issuer should be rejected")
	}
	// Redirecting discovery URL.
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/other", http.StatusFound)
	}))
	defer redirector.Close()
	_, err = oidc.NewProvider(context.Background(), oidc.Config{
		ProviderID: "acme", ClientID: "client-id", Issuer: redirector.URL, HTTPClient: redirector.Client(),
	})
	if err == nil {
		t.Fatal("redirecting discovery should be rejected")
	}
}

func TestOIDCDiscoveryURLKeepsTenantPath(t *testing.T) {
	var requestedPath string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		requestedPath = r.URL.Path
		base := "https://idp.example.com"
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer server.Close()
	_, err := oidc.NewProvider(context.Background(), oidc.Config{
		ProviderID: "acme", ClientID: "client-id",
		Issuer:       "https://idp.example.com",
		DiscoveryURL: server.URL + "/tenant/.well-known/openid-configuration",
		HTTPClient:   server.Client(),
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if requestedPath != "/tenant/.well-known/openid-configuration" {
		t.Fatalf("discovery path = %q", requestedPath)
	}
}

func TestOIDCIssuerMismatchRejected(t *testing.T) {
	d := newDiscoveryServer(t, nil)
	defer d.server.Close()
	cfg := d.config("acme")
	cfg.Issuer = "https://other.example.com"
	_, err := oidc.NewProvider(context.Background(), cfg)
	if err == nil {
		t.Fatal("issuer mismatch should be rejected")
	}
}

func TestOIDCAlgorithmRejection(t *testing.T) {
	for name, algorithms := range map[string][]string{
		"none":        {"none"},
		"hs256":       {"HS256"},
		"unsupported": {"XYZ"},
	} {
		t.Run(name, func(t *testing.T) {
			d := newDiscoveryServer(t, map[string]any{"id_token_signing_alg_values_supported": algorithms})
			defer d.server.Close()
			_, err := oidc.NewProvider(context.Background(), d.config("acme"))
			if err == nil {
				t.Fatalf("algorithms %v should be rejected", algorithms)
			}
		})
	}
}

func TestOIDCExplicitEndpointsOverrideDiscovery(t *testing.T) {
	d := newDiscoveryServer(t, map[string]any{"authorization_endpoint": "https://bad.example.com/authorize"})
	defer d.server.Close()
	cfg := d.config("acme")
	cfg.AuthorizationURL = d.server.URL + "/authorize"
	provider, err := oidc.NewProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	url := provider.AuthURL("", "https://api.example.com/auth/oauth/callback", "state", "challenge")
	if !stringsPrefix(url, d.server.URL) {
		t.Fatalf("explicit endpoint not used: %q", url)
	}
}

func stringsPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}

func TestOIDCAuthorizationURLHasNonceAndOpenID(t *testing.T) {
	d := newDiscoveryServer(t, nil)
	defer d.server.Close()
	provider, err := oidc.NewProvider(context.Background(), d.config("acme"))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	withNonce, ok := any(provider).(signet.AuthURLWithNonce)
	if !ok {
		t.Fatal("OIDC provider must implement AuthURLWithNonce")
	}
	raw := withNonce.AuthURLWithNonce("", "https://api.example.com/auth/oauth/callback", "state", "challenge", "nonce-value")
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	query := parsed.Query()
	for key, want := range map[string]string{
		"nonce": "nonce-value", "code_challenge": "challenge",
		"code_challenge_method": "S256", "scope": "openid",
	} {
		if query.Get(key) != want {
			t.Fatalf("%s = %q, want %q", key, query.Get(key), want)
		}
	}
}

func TestOAuthStartSendsNonce(t *testing.T) {
	d := newDiscoveryServer(t, nil)
	defer d.server.Close()
	provider, err := oidc.NewProvider(context.Background(), d.config("acme"))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.OAuth = &signet.OAuthConfig{
		Providers:        []signet.OAuthProvider{provider},
		RedirectBaseURL:  "https://api.example.com",
		AllowedRedirects: []string{"https://app.example.com/callback"},
		StateKey:         make([]byte, 32),
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := client.OAuthStart(context.Background(), signet.OAuthStartInput{
		Provider: "acme", Redirect: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("OAuthStart: %v", err)
	}
	parsed, err := url.Parse(result.URL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	if parsed.Query().Get("nonce") == "" {
		t.Fatalf("authorization URL has no nonce: %q", result.URL)
	}
}

type nonceRecordingProvider struct{ seen string }

func (p *nonceRecordingProvider) Name() string { return "recording" }
func (p *nonceRecordingProvider) AuthURL(_, _, state, _ string) string {
	return "https://example.com/authorize?state=" + url.QueryEscape(state)
}

func (p *nonceRecordingProvider) AuthURLWithNonce(_, _, state, _, nonce string) string {
	return "https://example.com/authorize?state=" + url.QueryEscape(state) + "&nonce=" + url.QueryEscape(nonce)
}
func (p *nonceRecordingProvider) Exchange(context.Context, string, string, string) (*signet.OAuthIdentity, error) {
	return nil, errors.New("not used")
}
func (p *nonceRecordingProvider) ExchangeWithNonce(_ context.Context, _, _, _, nonce string) (*signet.OAuthIdentity, error) {
	p.seen = nonce
	return &signet.OAuthIdentity{
		Provider: "recording", ProviderUserID: "user", Email: "user@example.com", EmailVerified: true,
	}, nil
}

func TestOAuthCallbackPassesNonceToProvider(t *testing.T) {
	recorder := &nonceRecordingProvider{}
	store := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.OAuth = &signet.OAuthConfig{
		Providers:        []signet.OAuthProvider{recorder},
		RedirectBaseURL:  "https://api.example.com",
		AllowedRedirects: []string{"https://app.example.com/callback"},
		StateKey:         make([]byte, 32),
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	started, err := client.OAuthStart(ctx, signet.OAuthStartInput{
		Provider: "recording", Redirect: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("OAuthStart: %v", err)
	}
	parsed, err := url.Parse(started.URL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	stateValue := parsed.Query().Get("state")
	nonceValue := parsed.Query().Get("nonce")
	if stateValue == "" || nonceValue == "" || len(store.Tokens) != 1 {
		t.Fatalf("start did not issue state and nonce: %q, %q, %d tokens", stateValue, nonceValue, len(store.Tokens))
	}
	if _, err := client.OAuthCallback(ctx, signet.OAuthCallbackInput{
		Code: "code", State: stateValue,
	}); err != nil {
		t.Fatalf("OAuthCallback: %v", err)
	}
	if recorder.seen != nonceValue {
		t.Fatalf("callback nonce = %q, want the sealed nonce %q", recorder.seen, nonceValue)
	}
}

func TestOIDCProviderIDConflicts(t *testing.T) {
	d := newDiscoveryServer(t, nil)
	defer d.server.Close()
	provider, err := oidc.NewProvider(context.Background(), d.config("acme"))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	{
		cfg := testutil.NewConfig()
		cfg.Store = testutil.NewStore()
		cfg.Mailer = testutil.NewMailer()
		cfg.RateLimiter = &testutil.Limiter{Allowed: true}
		cfg.OAuth = &signet.OAuthConfig{
			Providers:        []signet.OAuthProvider{provider, provider},
			RedirectBaseURL:  "https://api.example.com",
			AllowedRedirects: []string{"https://app.example.com/callback"},
			StateKey:         make([]byte, 32),
		}
		if _, err := signet.New(cfg); !errors.Is(err, signet.ErrOAuthProviderConflict) {
			t.Fatalf("duplicate provider error = %v", err)
		}
	}
}

func TestOIDCReservedProviderNameRejected(t *testing.T) {
	d := newDiscoveryServer(t, nil)
	defer d.server.Close()
	cfg := d.config("google")
	if _, err := oidc.NewProvider(context.Background(), cfg); !errors.Is(err, signet.ErrOAuthProviderConflict) {
		t.Fatalf("reserved provider error = %v", err)
	}
}
