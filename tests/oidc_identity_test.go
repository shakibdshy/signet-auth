package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
	"github.com/shakibdshy/signet-auth/oauth/oidc"
)

type oidcFixture struct {
	server       *httptest.Server
	key          *rsa.PrivateKey
	claims       map[string]any
	nonce        string
	badNonce     bool
	authHeader   string
	omitUserInfo bool
	userInfo     map[string]any
	jwks         map[string]any
	sendToken    bool
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &oidcFixture{key: key, sendToken: true}
	f.userInfo = map[string]any{
		"sub": "user-1", "email": "user@example.com", "email_verified": true, "name": "Ada",
	}
	f.jwks = map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": "test-key", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := f.server.URL
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			doc := map[string]any{
				"issuer":                                base,
				"authorization_endpoint":                base + "/authorize",
				"token_endpoint":                        base + "/token",
				"jwks_uri":                              base + "/jwks",
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
			}
			if !f.omitUserInfo {
				doc["userinfo_endpoint"] = base + "/userinfo"
			}
			_ = json.NewEncoder(w).Encode(doc)
		case "/token":
			f.authHeader = r.Header.Get("Authorization")
			body := map[string]any{"access_token": "access", "token_type": "Bearer"}
			if f.sendToken {
				claims := map[string]any{}
				for k, v := range f.claims {
					claims[k] = v
				}
				if f.badNonce {
					claims["nonce"] = "wrong-nonce"
				} else {
					claims["nonce"] = f.nonce
				}
				raw, _ := f.makeToken(claims)
				body["id_token"] = raw
			}
			_ = json.NewEncoder(w).Encode(body)
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(f.userInfo)
		case "/jwks":
			_ = json.NewEncoder(w).Encode(f.jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	f.claims = map[string]any{
		"sub": "user-1", "email": "user@example.com", "email_verified": true,
	}
	return f
}

func (f *oidcFixture) makeToken(claims map[string]any) (string, error) {
	now := time.Now()
	all := map[string]any{
		"iss": f.serverURL(), "aud": "client-id", "exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	for k, v := range claims {
		all[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(all))
	token.Header["kid"] = "test-key"
	return token.SignedString(f.key)
}

func (f *oidcFixture) makeIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	raw, err := f.makeToken(claims)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *oidcFixture) serverURL() string {
	if f.server == nil {
		return ""
	}
	return f.server.URL
}

func (f *oidcFixture) providerConfig() oidc.Config {
	return oidc.Config{
		ProviderID: "acme", ClientID: "client-id", ClientSecret: "client-secret",
		Issuer: f.server.URL, HTTPClient: f.server.Client(),
	}
}

func (f *oidcFixture) client(t *testing.T, provider signet.OAuthProvider) *signet.Client {
	t.Helper()
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
	return client
}

func (f *oidcFixture) signIn(t *testing.T, client *signet.Client) (*signet.OAuthCallbackResult, error) {
	t.Helper()
	ctx := context.Background()
	started, err := client.OAuthStart(ctx, signet.OAuthStartInput{
		Provider: "acme", Redirect: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("OAuthStart: %v", err)
	}
	parsed, err := url.Parse(started.URL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	f.nonce = parsed.Query().Get("nonce")
	return client.OAuthCallback(ctx, signet.OAuthCallbackInput{
		Code: "code", State: parsed.Query().Get("state"),
	})
}

func TestOIDCIdentityVerifiedIDToken(t *testing.T) {
	f := newOIDCFixture(t)
	defer f.server.Close()
	provider, err := oidc.NewProvider(context.Background(), f.providerConfig())
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	client := f.client(t, provider)
	result, err := f.signIn(t, client)
	if err != nil {
		t.Fatalf("OAuthCallback: %v", err)
	}
	if result.User.Email != "user@example.com" || result.User.EmailVerified != true {
		t.Fatalf("user = %+v", result.User)
	}
	if result.LastSignInMethod != "acme" {
		t.Fatalf("method = %q", result.LastSignInMethod)
	}
}

func TestOIDCIdentityRejectsBadTokenClaims(t *testing.T) {
	for name, claims := range map[string]map[string]any{
		"wrong issuer":     {"sub": "user-1", "iss": "https://evil.example.com", "nonce": "expected-nonce"},
		"wrong audience":   {"sub": "user-1", "aud": "other", "nonce": "expected-nonce"},
		"expired":          {"sub": "user-1", "exp": time.Now().Add(-time.Hour).Unix(), "nonce": "expected-nonce"},
		"nonce mismatch":   {"sub": "user-1"},
		"subject mismatch": {"sub": "other-sub", "nonce": "expected-nonce"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newOIDCFixture(t)
			defer f.server.Close()
			f.claims = claims
			f.badNonce = name == "nonce mismatch"
			provider, err := oidc.NewProvider(context.Background(), f.providerConfig())
			if err != nil {
				t.Fatalf("NewProvider: %v", err)
			}
			client := f.client(t, provider)
			if _, err := f.signIn(t, client); err == nil {
				t.Fatal("expected token verification to fail")
			}
		})
	}
}

func TestOIDCIdentityUserInfoFallback(t *testing.T) {
	f := newOIDCFixture(t)
	defer f.server.Close()
	f.sendToken = false
	provider, err := oidc.NewProvider(context.Background(), f.providerConfig())
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	client := f.client(t, provider)
	result, err := f.signIn(t, client)
	if err != nil {
		t.Fatalf("OAuthCallback: %v", err)
	}
	if result.User.Email != "user@example.com" || !result.User.EmailVerified {
		t.Fatalf("user = %+v", result.User)
	}
}

func TestOIDCIdentityJWKSFailureIsHardError(t *testing.T) {
	f := newOIDCFixture(t)
	defer f.server.Close()
	cfg := f.providerConfig()
	cfg.JWKSURI = f.server.URL + "/missing-jwks"
	provider, err := oidc.NewProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	client := f.client(t, provider)
	if _, err := f.signIn(t, client); err == nil || strings.Contains(err.Error(), "verification") {
		t.Fatalf("JWKS fetch failure must be a hard error: %v", err)
	}
}

func TestOIDCTokenAuthPrefersBasic(t *testing.T) {
	f := newOIDCFixture(t)
	defer f.server.Close()
	provider, err := oidc.NewProvider(context.Background(), f.providerConfig())
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	client := f.client(t, provider)
	if _, err := f.signIn(t, client); err != nil {
		t.Fatalf("OAuthCallback: %v", err)
	}
	if !strings.HasPrefix(f.authHeader, "Basic ") {
		t.Fatalf("token auth header = %q", f.authHeader)
	}
}

func TestOIDCIdentityVerifiedTokenAlone(t *testing.T) {
	f := newOIDCFixture(t)
	defer f.server.Close()
	f.omitUserInfo = true
	provider, err := oidc.NewProvider(context.Background(), f.providerConfig())
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	client := f.client(t, provider)
	result, err := f.signIn(t, client)
	if err != nil {
		t.Fatalf("OAuthCallback: %v", err)
	}
	if result.User.Email != "user@example.com" || !result.User.EmailVerified {
		t.Fatalf("user = %+v", result.User)
	}
}

func TestOIDCPerFieldEmailFallback(t *testing.T) {
	f := newOIDCFixture(t)
	defer f.server.Close()
	f.claims = map[string]any{"sub": "user-1", "email": "token@example.com"}
	f.userInfo["email"] = "userinfo@example.com"
	f.userInfo["email_verified"] = true
	provider, err := oidc.NewProvider(context.Background(), f.providerConfig())
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	client := f.client(t, provider)
	result, err := f.signIn(t, client)
	if err != nil {
		t.Fatalf("OAuthCallback: %v", err)
	}
	if result.User.Email != "token@example.com" || !result.User.EmailVerified {
		t.Fatalf("user = %+v", result.User)
	}
}
