package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestOIDCProviderIDConflicts(t *testing.T) {
	d := newDiscoveryServer(t, nil)
	defer d.server.Close()
	provider, err := oidc.NewProvider(context.Background(), d.config("acme"))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	for _, name := range []string{"google", "github", "acme"} {
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
		_ = name
		if _, err := signet.New(cfg); !errors.Is(err, signet.ErrOAuthProviderConflict) {
			t.Fatalf("duplicate provider error = %v", err)
		}
		break
	}
}

func TestOIDCReservedProviderNameRejected(t *testing.T) {
	d := newDiscoveryServer(t, nil)
	defer d.server.Close()
	cfg := d.config("google")
	if _, err := oidc.NewProvider(context.Background(), cfg); err == nil {
		t.Fatal("reserved provider name should be rejected")
	}
}

var _ = fmt.Sprintf
