package signet_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

var testJWTKey = []byte("a-long-test-signing-key-for-hs256-only")

func jwtClient(t *testing.T) (*signet.Client, *testutil.Store) {
	t.Helper()
	store := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.JWT = &signet.JWTConfig{Algorithm: "HS256", Key: testJWTKey}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, store
}

func TestJWTDisabledByDefault(t *testing.T) {
	client, _, _ := newAuthClient()
	_, err := client.ExchangeToken(context.Background(), signet.TokenInput{Email: "user@example.com", Password: "password123"})
	if !errors.Is(err, signet.ErrJWTDisabled) {
		t.Fatalf("ExchangeToken error = %v, want ErrJWTDisabled", err)
	}
}

func TestJWTConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		jwt  *signet.JWTConfig
		want error
	}{
		{"missing algorithm", &signet.JWTConfig{Key: testJWTKey}, signet.ErrInvalidJWTAlgorithm},
		{"none algorithm", &signet.JWTConfig{Key: testJWTKey, Algorithm: "none"}, signet.ErrInvalidJWTAlgorithm},
		{"wrong key type", &signet.JWTConfig{Key: "string key", Algorithm: "RS256"}, signet.ErrInvalidJWTKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testutil.NewConfig()
			cfg.Store = testutil.NewStore()
			cfg.Mailer = fakeMailer{}
			cfg.RateLimiter = &testutil.Limiter{Allowed: true}
			cfg.JWT = tt.jwt
			if _, err := signet.New(cfg); !errors.Is(err, tt.want) {
				t.Fatalf("New error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestTokenExchangeIssuesVerifiableAccessToken(t *testing.T) {
	client, _ := jwtClient(t)
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	pair, err := client.ExchangeToken(context.Background(), signet.TokenInput{Email: "user@example.com", Password: "password123"})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" || pair.ExpiresIn <= 0 {
		t.Fatalf("pair = %+v, want both tokens and an expiry", pair)
	}
	user, err := client.VerifyAccessToken(context.Background(), pair.AccessToken)
	if err != nil || user.Email != "user@example.com" {
		t.Fatalf("VerifyAccessToken = (%v, %v)", user, err)
	}
}

func TestRefreshRotatesAndDetectsReuse(t *testing.T) {
	client, store := jwtClient(t)
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	first, err := client.ExchangeToken(context.Background(), signet.TokenInput{Email: "user@example.com", Password: "password123"})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	second, err := client.ExchangeToken(context.Background(), signet.TokenInput{RefreshToken: first.RefreshToken})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("refresh token was not rotated")
	}
	if _, err := client.ExchangeToken(context.Background(), signet.TokenInput{RefreshToken: first.RefreshToken}); !errors.Is(err, signet.ErrRefreshReuse) {
		t.Fatalf("replayed refresh error = %v, want ErrRefreshReuse", err)
	}
	if len(store.Sessions) != 0 || len(store.Tokens) != 0 {
		t.Errorf("reuse should revoke Sessions and Tokens; got %d sessions, %d tokens", len(store.Sessions), len(store.Tokens))
	}
}

func TestTokenEndpointHTTP(t *testing.T) {
	client, _ := jwtClient(t)
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	body := `{"email":"user@example.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	for _, field := range []string{"access_token", "refresh_token", "expires_in"} {
		if !strings.Contains(rec.Body.String(), field) {
			t.Errorf("body = %s, want %s", rec.Body.String(), field)
		}
	}
}

func TestTokenEndpointRejectsNonPOST(t *testing.T) {
	client, _ := jwtClient(t)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/token", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestRefreshReuseRevokesAllTokenKinds(t *testing.T) {
	client, store := jwtClient(t)
	user, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "password123",
	})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := store.CreateToken(context.Background(), &signet.Token{
		ID: "verification", UserID: user.User.ID, Kind: signet.TokenVerifyEmail, Hash: "digest",
	}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	first, err := client.ExchangeToken(context.Background(), signet.TokenInput{Email: "user@example.com", Password: "password123"})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if _, err := client.ExchangeToken(context.Background(), signet.TokenInput{RefreshToken: first.RefreshToken}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := client.ExchangeToken(context.Background(), signet.TokenInput{RefreshToken: first.RefreshToken}); !errors.Is(err, signet.ErrRefreshReuse) {
		t.Fatalf("replay error = %v, want ErrRefreshReuse", err)
	}
	if len(store.Tokens) != 0 {
		t.Errorf("tokens = %d, want all kinds revoked", len(store.Tokens))
	}
}

func TestAccessTokenExpiryIsShort(t *testing.T) {
	client, _ := jwtClient(t)
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	pair, err := client.ExchangeToken(context.Background(), signet.TokenInput{Email: "user@example.com", Password: "password123"})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if pair.ExpiresIn > int64((15*time.Minute)/time.Second) {
		t.Errorf("ExpiresIn = %d, want at most 15 minutes", pair.ExpiresIn)
	}
}
