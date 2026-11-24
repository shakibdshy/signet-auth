package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

func verificationClient(t *testing.T) (*signet.Client, *testutil.Store, *testutil.Mailer) {
	t.Helper()
	store := testutil.NewStore()
	mailer := &testutil.Mailer{}
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.RequireVerifiedEmail = testutil.BoolPtr(true)
	cfg.SendVerificationOnSignUp = testutil.BoolPtr(true)
	cfg.AppURL = "https://app.example.com"
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, store, mailer
}

func tokenFromMessage(t *testing.T, msg signet.Message) string {
	t.Helper()
	for _, line := range strings.Split(msg.TextBody, "\n") {
		if !strings.HasPrefix(line, "https://") {
			continue
		}
		parsed, err := url.Parse(line)
		if err != nil {
			t.Fatalf("parse link: %v", err)
		}
		return parsed.Query().Get("token")
	}
	t.Fatalf("no link in message: %s", msg.TextBody)
	return ""
}

func TestSignUpSendsVerificationEmail(t *testing.T) {
	client, _, mailer := verificationClient(t)
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if len(mailer.Messages) != 1 || !strings.Contains(mailer.Messages[0].Subject, "Verify") {
		t.Fatalf("messages = %+v, want one verification email", mailer.Messages)
	}
	if tokenFromMessage(t, mailer.Messages[0]) == "" {
		t.Error("verification message has no token")
	}
}

func TestSignUpKeepsUserWhenMailFails(t *testing.T) {
	client, store, mailer := verificationClient(t)
	mailer.Fail = true
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"}); err == nil {
		t.Fatal("SignUp error = nil, want mail delivery error")
	}
	if len(store.Users) != 1 {
		t.Errorf("users = %d, want the User retained", len(store.Users))
	}
}

func TestUnverifiedSignInIsRejected(t *testing.T) {
	client, _, _ := verificationClient(t)
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"}); !errors.Is(err, signet.ErrEmailNotVerified) {
		t.Fatalf("SignIn error = %v, want ErrEmailNotVerified", err)
	}
}

func TestUnverifiedSignInHTTPIsForbidden(t *testing.T) {
	client, _, _ := verificationClient(t)
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(`{"email":"user@example.com","password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "email_not_verified") {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestVerifyEmailMarksUserVerifiedAndIsSingleUse(t *testing.T) {
	client, store, mailer := verificationClient(t)
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	token := tokenFromMessage(t, mailer.Messages[0])
	if err := client.VerifyEmail(context.Background(), signet.VerifyEmailInput{Token: token}); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	for _, user := range store.Users {
		if !user.EmailVerified {
			t.Error("User was not marked verified")
		}
	}
	if err := client.VerifyEmail(context.Background(), signet.VerifyEmailInput{Token: token}); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("replayed VerifyEmail error = %v, want ErrTokenInvalid", err)
	}
	if _, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignIn after verification: %v", err)
	}
}

func TestResendVerificationInvalidatesOldToken(t *testing.T) {
	client, _, mailer := verificationClient(t)
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	first := tokenFromMessage(t, mailer.Messages[0])
	if err := client.SendVerification(context.Background(), signet.SendVerificationInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendVerification: %v", err)
	}
	if len(mailer.Messages) != 2 {
		t.Fatalf("messages = %d, want 2", len(mailer.Messages))
	}
	second := tokenFromMessage(t, mailer.Messages[1])
	if first == second {
		t.Error("resend produced the same token")
	}
	if err := client.VerifyEmail(context.Background(), signet.VerifyEmailInput{Token: first}); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("old token error = %v, want ErrTokenInvalid", err)
	}
	if err := client.VerifyEmail(context.Background(), signet.VerifyEmailInput{Token: second}); err != nil {
		t.Fatalf("new token: %v", err)
	}
}

func TestSendVerificationHidesUnknownEmail(t *testing.T) {
	client, _, mailer := verificationClient(t)
	if err := client.SendVerification(context.Background(), signet.SendVerificationInput{Email: "nobody@example.com"}); err != nil {
		t.Fatalf("SendVerification(unknown) = %v, want nil", err)
	}
	if len(mailer.Messages) != 0 {
		t.Errorf("messages = %d, want none for an unknown email", len(mailer.Messages))
	}
}

func TestVerificationEndpoints(t *testing.T) {
	client, _, mailer := verificationClient(t)
	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		client.Handler().ServeHTTP(rec, req)
		return rec
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if rec := post("/send-verification", `{"email":"user@example.com"}`); rec.Code != http.StatusOK {
		t.Fatalf("send status = %d, body = %s", rec.Code, rec.Body.String())
	}
	token := tokenFromMessage(t, mailer.Messages[len(mailer.Messages)-1])
	if rec := post("/verify-email", `{"token":"`+token+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d, body = %s", rec.Code, rec.Body.String())
	}
}
