package signet_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
)

func signUp(client *signet.Client) error {
	_, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"})
	return err
}

func TestSignInCreatesSessionWithHashedToken(t *testing.T) {
	client, store, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(context.Background(), signet.SignInInput{
		Email: "user@example.com", Password: "password123",
	})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if result.User == nil || result.SessionToken == "" {
		t.Fatalf("SignIn result = %+v, want a User and a Session token", result)
	}
	if len(store.sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(store.sessions))
	}
	var stored *signet.Session
	for _, session := range store.sessions {
		stored = session
	}
	if stored.TokenHash == "" || stored.TokenHash == result.SessionToken {
		t.Errorf("stored token hash = %q; raw token must never be stored", stored.TokenHash)
	}
	if stored.UserID != result.User.ID || !stored.IdleExpiresAt.After(testTime) || !stored.AbsoluteExpiresAt.After(testTime) {
		t.Errorf("Session = %+v, want owner and future expiries", stored)
	}
}

func TestSignInFailuresAreGenericAndUseDummyVerifier(t *testing.T) {
	hasher := &versionedHasher{version: 1}
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.PasswordHasher = hasher
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.SignIn(context.Background(), signet.SignInInput{Email: "nobody@example.com", Password: "password123"})
	if !errors.Is(err, signet.ErrInvalidCredentials) {
		t.Fatalf("SignIn(unknown) error = %v, want ErrInvalidCredentials", err)
	}
	if hasher.verifyCalls != 1 {
		t.Errorf("Verify calls = %d, want 1 dummy verification", hasher.verifyCalls)
	}
}

func TestSignInRehashesStaleVerifier(t *testing.T) {
	hasher := &versionedHasher{version: 1}
	store := newMemoryStore()
	cfg := testConfig()
	cfg.Store = store
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.PasswordHasher = hasher
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	hasher.version = 2
	if _, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignIn after parameter change: %v", err)
	}
	if len(store.accounts) != 1 || !strings.HasPrefix(store.accounts[0].PasswordHash, "v2:") {
		t.Errorf("credential Account verifier = %+v, want upgraded version", store.accounts)
	}
}

func TestSignInRejectsDisabledUser(t *testing.T) {
	client, store, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	store.usersByEmail["user@example.com"].Disabled = true
	if _, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"}); !errors.Is(err, signet.ErrInvalidCredentials) {
		t.Fatalf("SignIn(disabled) error = %v, want ErrInvalidCredentials", err)
	}
}

func TestRehashFailureDoesNotAbortSignIn(t *testing.T) {
	hasher := &rehashFailureHasher{}
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.PasswordHasher = hasher
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignIn with a failing rehash = %v, want success", err)
	}
}

func TestSignInEnforcesMinimumPasswordLength(t *testing.T) {
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.PasswordHasher = fastHasher{}
	cfg.Password.MinLength = 12
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password1234"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "short"}); !errors.Is(err, signet.ErrPasswordTooShort) {
		t.Fatalf("SignIn(short) error = %v, want ErrPasswordTooShort", err)
	}
}

func TestSignInHTTPEndpoint(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(`{"email":"user@example.com","password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.SessionToken == "" {
		t.Errorf("response = %s, want a session token", rec.Body.String())
	}
}

func TestSignInHTTPFailureIsGeneric(t *testing.T) {
	client, _, _ := newAuthClient()
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(`{"email":"nobody@example.com","password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", rec.Code, rec.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response["error"] != "invalid_credentials" {
		t.Errorf("error body = %s, want invalid_credentials", rec.Body.String())
	}
}
