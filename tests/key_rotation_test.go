package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

func ringJWTClient(t *testing.T, store signet.Store, configure func(*signet.JWTConfig)) *signet.Client {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.JWT = &signet.JWTConfig{Algorithm: "HS256", Key: []byte("legacy-key-12345678901234567890")}
	configure(cfg.JWT)
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestJWTLegacySingleKeyStillWorks(t *testing.T) {
	store := testutil.NewStore()
	client := ringJWTClient(t, store, func(*signet.JWTConfig) {})
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	pair, err := client.ExchangeToken(ctx, signet.TokenInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	user, err := client.VerifyAccessToken(ctx, pair.AccessToken)
	if err != nil || user.Email != "user@example.com" {
		t.Fatalf("VerifyAccessToken = %+v, %v", user, err)
	}
}

func TestJWTRingSignsWithFirstAndVerifiesOlderKey(t *testing.T) {
	store := testutil.NewStore()
	first := []byte("new-active-key-1234567890123456")
	older := []byte("old-verification-key-1234567890")
	signer := ringJWTClient(t, store, func(cfg *signet.JWTConfig) {
		cfg.Key = older
	})
	verifier := ringJWTClient(t, store, func(cfg *signet.JWTConfig) {
		cfg.Key = nil
		cfg.Keys = []any{first, older}
	})
	ctx := context.Background()
	if _, err := signer.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	pair, err := signer.ExchangeToken(ctx, signet.TokenInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	user, err := verifier.VerifyAccessToken(ctx, pair.AccessToken)
	if err != nil || user.Email != "user@example.com" {
		t.Fatalf("older key did not verify token: %+v, %v", user, err)
	}
}

func TestJWKSHandlerPublishesAsymmetricKeysOnly(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	secondRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("second rsa.GenerateKey: %v", err)
	}
	store := testutil.NewStore()
	client := ringJWTClient(t, store, func(cfg *signet.JWTConfig) {
		cfg.Algorithm = "RS256"
		cfg.Key = nil
		cfg.Keys = []any{rsaKey, secondRSA}
	})
	rr := httptest.NewRecorder()
	client.JWKSHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/jwks.json", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	var document struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(document.Keys) != 2 {
		t.Fatalf("keys = %+v, want 2", document.Keys)
	}
	for _, key := range document.Keys {
		if key["kid"] == "" || key["alg"] == nil || key["use"] != "sig" {
			t.Fatalf("incomplete JWK: %+v", key)
		}
		for _, privateField := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, present := key[privateField]; present {
				t.Fatalf("private field %q in JWK: %+v", privateField, key)
			}
		}
	}
}

func TestAsymmetricAccessTokenHasMatchingKid(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	store := testutil.NewStore()
	client := ringJWTClient(t, store, func(cfg *signet.JWTConfig) {
		cfg.Algorithm = "RS256"
		cfg.Key = nil
		cfg.Keys = []any{rsaKey}
	})
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	pair, err := client.ExchangeToken(ctx, signet.TokenInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	parts := strings.Split(pair.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT: %q", pair.AccessToken)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Kid == "" {
		t.Fatalf("header = %s, err = %v", headerBytes, err)
	}

	rr := httptest.NewRecorder()
	client.JWKSHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/jwks.json", nil))
	var document struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(document.Keys) != 1 || document.Keys[0].Kid != header.Kid {
		t.Fatalf("JWKS kid %+v does not match token kid %q", document.Keys, header.Kid)
	}
}

func TestJWKSHandlerEmptyForSymmetricKeys(t *testing.T) {
	client := ringJWTClient(t, testutil.NewStore(), func(*signet.JWTConfig) {})
	rr := httptest.NewRecorder()
	client.JWKSHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/jwks.json", nil))
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != `{"keys":[]}` {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestJWKSPathIsNotMountedImplicitly(t *testing.T) {
	client := ringJWTClient(t, testutil.NewStore(), func(*signet.JWTConfig) {})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/jwks.json", nil)
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestJWTRingRejectsInvalidConfiguration(t *testing.T) {
	for name, configure := range map[string]func(*signet.JWTConfig){
		"empty ring": func(cfg *signet.JWTConfig) { cfg.Key = nil; cfg.Keys = nil },
		"wrong key type": func(cfg *signet.JWTConfig) {
			cfg.Key = nil
			cfg.Keys = []any{"not-bytes"}
		},
		"duplicate keys": func(cfg *signet.JWTConfig) {
			cfg.Key = nil
			cfg.Keys = []any{[]byte("same-key-123456789012345678"), []byte("same-key-123456789012345678")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testutil.NewConfig()
			cfg.Store = testutil.NewStore()
			cfg.Mailer = testutil.NewMailer()
			cfg.RateLimiter = &testutil.Limiter{Allowed: true}
			cfg.JWT = &signet.JWTConfig{Algorithm: "HS256"}
			configure(cfg.JWT)
			if _, err := signet.New(cfg); !errors.Is(err, signet.ErrInvalidKeyRing) {
				t.Fatalf("error = %v, want ErrInvalidKeyRing", err)
			}
		})
	}
}
