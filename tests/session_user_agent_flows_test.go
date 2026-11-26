package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

// userAgentOfFirstSession lists Sessions over HTTP with the given cookie and
// returns the user_agent of the only Session.
func userAgentOfFirstSession(t *testing.T, client *signet.Client, cookie *http.Cookie) string {
	t.Helper()
	sessions := listSessionsOverHTTP(t, client, cookie)
	got, ok := sessions[0]["user_agent"].(string)
	if !ok {
		t.Fatalf("session user_agent missing or not a string")
	}
	return got
}

func getWithUserAgent(t *testing.T, client *signet.Client, path, userAgent string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	return rec
}

func TestMagicLinkVerificationRecordsUserAgent(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	rec := getWithUserAgent(t, client, "/verify-magic-link?token="+magicLinkTokenFromMail(t, mailer), testUserAgent)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /verify-magic-link status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if got := userAgentOfFirstSession(t, client, sessionCookieFromResponse(t, rec)); got != testUserAgent {
		t.Fatalf("magic-link Session user_agent = %#v, want %#v", got, testUserAgent)
	}
}

func TestEmailOTPVerificationRecordsUserAgent(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	req := httptest.NewRequest(http.MethodPost, "/verify-otp", strings.NewReader(`{"email":"user@example.com","code":"`+code+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", testUserAgent)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /verify-otp status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if got := userAgentOfFirstSession(t, client, sessionCookieFromResponse(t, rec)); got != testUserAgent {
		t.Fatalf("OTP Session user_agent = %#v, want %#v", got, testUserAgent)
	}
}

func TestSignUpAutoSignInRecordsUserAgent(t *testing.T) {
	store := testutil.NewStore()
	mailer := testutil.NewMailer()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AutoSignIn = &signet.AutoSignInConfig{AfterSignUp: true}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(`{"email":"user@example.com","password":"correct horse"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", testUserAgent)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /signup status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if got := userAgentOfFirstSession(t, client, sessionCookieFromResponse(t, rec)); got != testUserAgent {
		t.Fatalf("sign-up Session user_agent = %#v, want %#v", got, testUserAgent)
	}
}

func TestVerificationAutoSignInRecordsUserAgent(t *testing.T) {
	no := false
	client, mailer := autoSignInClient(t, false, true, &no, new(int), nil)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/verify-email", strings.NewReader(`{"token":"`+verificationToken(t, mailer)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", testUserAgent)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /verify-email status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if got := userAgentOfFirstSession(t, client, sessionCookieFromResponse(t, rec)); got != testUserAgent {
		t.Fatalf("verification Session user_agent = %#v, want %#v", got, testUserAgent)
	}
}

func TestProgrammaticSignInRecordsEmptyUserAgent(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	list, err := client.ListSessions(context.Background(), signet.ListSessionsInput{UserID: result.User.ID})
	if err != nil || len(list.Sessions) != 1 {
		t.Fatalf("ListSessions = (%v, %v)", list, err)
	}
	if got := list.Sessions[0].UserAgent; got != "" {
		t.Fatalf("programmatic Session UserAgent = %#v, want an empty string", got)
	}
}
