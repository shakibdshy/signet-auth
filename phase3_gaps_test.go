package signet_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
)

func TestVerificationTokenExpiryUsesClock(t *testing.T) {
	clock := &adjustableClock{at: testTime}
	store := newMemoryStore()
	mailer := &capturingMailer{}
	cfg := testConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.Clock = clock
	cfg.SendVerificationOnSignUp = boolPtr(true)
	cfg.AppURL = "https://app.example.com"
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	token := tokenFromMessage(t, mailer.messages[0])
	clock.at = testTime.Add(25 * time.Hour)
	if err := client.VerifyEmail(context.Background(), signet.VerifyEmailInput{Token: token}); !errors.Is(err, signet.ErrTokenExpired) {
		t.Fatalf("expired verification error = %v, want ErrTokenExpired", err)
	}
}

func rateLimitedPhase3Client(t *testing.T) *signet.Client {
	t.Helper()
	cfg := testConfig()
	cfg.Store = newMemoryStore()
	cfg.Mailer = &capturingMailer{}
	cfg.RateLimiter = &recordingLimiter{allow: false}
	cfg.AppURL = "https://app.example.com"
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestVerificationSendRateLimited(t *testing.T) {
	client := rateLimitedPhase3Client(t)
	req := httptest.NewRequest(http.MethodPost, "/send-verification", strings.NewReader(`{"email":"user@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body = %s", rec.Code, rec.Body.String())
	}
}

func TestVerificationConsumeRateLimited(t *testing.T) {
	client := rateLimitedPhase3Client(t)
	req := httptest.NewRequest(http.MethodPost, "/verify-email", strings.NewReader(`{"token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body = %s", rec.Code, rec.Body.String())
	}
}

func TestPasswordResetSendRateLimited(t *testing.T) {
	client := rateLimitedPhase3Client(t)
	req := httptest.NewRequest(http.MethodPost, "/send-password-reset", strings.NewReader(`{"email":"user@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body = %s", rec.Code, rec.Body.String())
	}
}

func TestPasswordResetConsumeRateLimited(t *testing.T) {
	client := rateLimitedPhase3Client(t)
	req := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader(`{"token":"x","new_password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body = %s", rec.Code, rec.Body.String())
	}
}

func TestConfigDefaultsApplyWithoutDefaultConfig(t *testing.T) {
	cfg := signet.Config{
		Store:       newMemoryStore(),
		Mailer:      &capturingMailer{},
		RateLimiter: &recordingLimiter{allow: true},
	}
	cfg.Cookie.Secure = true
	cfg.Cookie.HttpOnly = true
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"}); !errors.Is(err, signet.ErrEmailNotVerified) {
		t.Fatalf("hand-built Config sign-in error = %v, want ErrEmailNotVerified", err)
	}
}

func TestPhase3FlowsDoNotLogSecrets(t *testing.T) {
	var logs bytes.Buffer
	store := newMemoryStore()
	mailer := &capturingMailer{}
	cfg := testConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &recordingLimiter{allow: true}
	cfg.SendVerificationOnSignUp = boolPtr(true)
	cfg.AppURL = "https://app.example.com"
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	verifyToken := tokenFromMessage(t, mailer.messages[0])
	if err := client.VerifyEmail(context.Background(), signet.VerifyEmailInput{Token: verifyToken}); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if err := client.SendPasswordReset(context.Background(), signet.SendPasswordResetInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}
	resetToken := tokenFromMessage(t, mailer.messages[len(mailer.messages)-1])
	if err := client.ResetPassword(context.Background(), signet.ResetPasswordInput{Token: resetToken, NewPassword: "a-new-password"}); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	output := logs.String()
	for _, secret := range []string{verifyToken, resetToken, "password123", "a-new-password", "https://app.example.com"} {
		if strings.Contains(output, secret) {
			t.Errorf("logs leaked %q: %s", secret, output)
		}
	}
}
