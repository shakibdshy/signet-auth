package signet_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
)

var testTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func newAuthClient() (*signet.Client, *memoryStore, *recordingLimiter) {
	store := newMemoryStore()
	limiter := &recordingLimiter{allow: true}
	var logs bytes.Buffer
	cfg := testConfig()
	cfg.Store = store
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = limiter
	cfg.PasswordHasher = fastHasher{}
	cfg.Clock = fixedClock{at: testTime}
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	client, err := signet.New(cfg)
	if err != nil {
		panic(err)
	}
	return client, store, limiter
}

func TestSignUpCreatesUserAndCredentialAccount(t *testing.T) {
	client, store, _ := newAuthClient()
	result, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email:    " User@Example.COM ",
		Password: "password123",
		Name:     "Ada",
	})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if result == nil || result.User == nil {
		t.Fatal("SignUp returned no User")
	}
	user := result.User
	if user.Email != "user@example.com" || user.ID == "" || !user.CreatedAt.Equal(testTime) {
		t.Errorf("User = %+v, want normalized email, an ID and the configured clock", user)
	}
	accounts, err := store.AccountsForUser(context.Background(), user.ID)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("AccountsForUser = (%v, %v), want one Account", accounts, err)
	}
	account := accounts[0]
	if account.Provider != "credential" || account.PasswordHash != "encoded:password123" || account.EmailVerified {
		t.Errorf("credential Account = %+v, want unverified credential with a verifier", account)
	}
}

func TestSignUpRejectsInvalidInput(t *testing.T) {
	client, _, _ := newAuthClient()
	tests := []struct {
		name  string
		input signet.SignUpInput
		want  error
	}{
		{"short password", signet.SignUpInput{Email: "a@example.com", Password: "short"}, signet.ErrPasswordTooShort},
		{"long password", signet.SignUpInput{Email: "a@example.com", Password: strings.Repeat("x", 129)}, signet.ErrPasswordTooLong},
		{"empty email", signet.SignUpInput{Email: "  ", Password: "password123"}, signet.ErrInvalidEmail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := client.SignUp(context.Background(), tt.input); !errors.Is(err, tt.want) {
				t.Fatalf("SignUp error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSignUpRejectsDuplicateEmail(t *testing.T) {
	client, _, _ := newAuthClient()
	input := signet.SignUpInput{Email: "user@example.com", Password: "password123"}
	if _, err := client.SignUp(context.Background(), input); err != nil {
		t.Fatalf("first SignUp: %v", err)
	}
	if _, err := client.SignUp(context.Background(), input); !errors.Is(err, signet.ErrEmailAlreadyExists) {
		t.Fatalf("second SignUp error = %v, want ErrEmailAlreadyExists", err)
	}
}

func TestSignUpRateLimited(t *testing.T) {
	client, _, limiter := newAuthClient()
	limiter.allow = false
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"}); !errors.Is(err, signet.ErrRateLimited) {
		t.Fatalf("SignUp error = %v, want ErrRateLimited", err)
	}
	if len(limiter.keys) != 1 || !strings.HasPrefix(limiter.keys[0], "signup|") {
		t.Errorf("limiter keys = %v, want one signup key", limiter.keys)
	}
}

func TestSignUpRollsBackUserWhenAccountFails(t *testing.T) {
	client, store, _ := newAuthClient()
	store.failAccountCreate = true
	_, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"})
	if err == nil {
		t.Fatal("SignUp error = nil, want store failure")
	}
	if len(store.users) != 0 || len(store.usersByEmail) != 0 {
		t.Errorf("rollback left %d Users behind", len(store.users))
	}
}

func TestSignUpEventsAndRedactedHook(t *testing.T) {
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.PasswordHasher = fastHasher{}
	cfg.Clock = fixedClock{at: testTime}
	var logs bytes.Buffer
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	var hooked *signet.User
	cfg.OnSignUp = func(_ context.Context, u *signet.User) { hooked = u }
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email:    "user@example.com",
		Password: "password123",
		Name:     "Ada",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if hooked == nil || hooked.Email != "" || hooked.Name != "" || hooked.ID == "" {
		t.Errorf("hook User = %+v, want a redacted copy with an ID", hooked)
	}
	output := logs.String()
	if !strings.Contains(output, "sign_up") {
		t.Errorf("logs = %q, want a sign_up event", output)
	}
	if !strings.Contains(output, "2026-01-02") {
		t.Errorf("logs = %q, want the configured Clock timestamp", output)
	}
	if strings.Contains(output, "password123") || strings.Contains(output, "user@example.com") {
		t.Errorf("logs leaked sensitive data: %q", output)
	}
}

func TestSignUpHTTPEndpoint(t *testing.T) {
	client, _, _ := newAuthClient()
	handler := client.Handler()
	body := `{"email":"user@example.com","password":"password123","name":"Ada"}`
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.User.Email != "user@example.com" {
		t.Errorf("response email = %q", response.User.Email)
	}
}

func TestSignUpHTTPRateLimited(t *testing.T) {
	client, _, limiter := newAuthClient()
	limiter.allow = false
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(`{"email":"user@example.com","password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body = %s", rec.Code, rec.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response["error"] != "rate_limited" {
		t.Errorf("error body = %s, want rate_limited", rec.Body.String())
	}
}

func TestSignUpHTTPValidationError(t *testing.T) {
	client, _, _ := newAuthClient()
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(`{"email":"a@example.com","password":"short"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response["error"] == "" {
		t.Errorf("error body = %s, want an error code", rec.Body.String())
	}
}
