package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
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
