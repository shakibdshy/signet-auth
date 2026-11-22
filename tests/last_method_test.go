package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

func lastMethodClient(t *testing.T, configure func(*signet.Config)) *signet.Client {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.LastSignInMethod = &signet.LastSignInMethodConfig{}
	if configure != nil {
		configure(&cfg)
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func signInHTTP(t *testing.T, client *signet.Client, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(body))
	client.Handler().ServeHTTP(rr, req)
	return rr
}

func cookieValue(rr *httptest.ResponseRecorder) *http.Cookie {
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "signet_last_method" {
			return cookie
		}
	}
	return nil
}

func TestLastMethodSetByHTTPSignIn(t *testing.T) {
	client := lastMethodClient(t, nil)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rr := signInHTTP(t, client, `{"email":"user@example.com","password":"correct horse"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	cookie := cookieValue(rr)
	if cookie == nil || !cookie.HttpOnly || cookie.Value == "" {
		t.Fatalf("last-method cookie = %+v", cookie)
	}
	read := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/last-sign-in-method", nil)
	req.AddCookie(cookie)
	client.Handler().ServeHTTP(read, req)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"method":"password"`) {
		t.Fatalf("read status = %d body = %s", read.Code, read.Body.String())
	}
}

func TestLastMethodGoResultAndConsent(t *testing.T) {
	client := lastMethodClient(t, func(cfg *signet.Config) {
		cfg.LastSignInMethod.BeforeStore = func(context.Context, string) bool { return false }
	})
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil || result.LastSignInMethod != "password" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	rr := signInHTTP(t, client, `{"email":"user@example.com","password":"correct horse"}`)
	if cookie := cookieValue(rr); cookie != nil {
		t.Fatalf("consent should skip the cookie: %+v", cookie)
	}
}

func TestLastMethodRejectsTamperedCookie(t *testing.T) {
	client := lastMethodClient(t, nil)
	read := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/last-sign-in-method", nil)
	req.AddCookie(&http.Cookie{Name: "signet_last_method", Value: "tampered.value", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	client.Handler().ServeHTTP(read, req)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"method":""`) {
		t.Fatalf("status = %d body = %s", read.Code, read.Body.String())
	}
}

func TestLastMethodClear(t *testing.T) {
	client := lastMethodClient(t, nil)
	rr := httptest.NewRecorder()
	client.ClearLastSignInMethod(rr)
	cookie := cookieValue(rr)
	if cookie == nil || cookie.MaxAge >= 0 {
		t.Fatalf("clear cookie = %+v", cookie)
	}
}

func TestLastMethodExpires(t *testing.T) {
	client := lastMethodClient(t, func(cfg *signet.Config) {
		cfg.LastSignInMethod.TTL = time.Minute
	})
	rr := httptest.NewRecorder()
	client.SetLastMethodCookie(rr, "password")
	cookie := cookieValue(rr)
	if cookie == nil || cookie.MaxAge != 60 {
		t.Fatalf("cookie = %+v", cookie)
	}
}

func TestLastMethodForUsername(t *testing.T) {
	client := lastMethodClient(t, nil)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse", Username: "ada",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(ctx, signet.SignInInput{Username: "ada", Password: "correct horse"})
	if err != nil || result.LastSignInMethod != "username" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestLastMethodForMagicLinkAndOTP(t *testing.T) {
	store := testutil.NewStore()
	mailer := testutil.NewMailer()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.LastSignInMethod = &signet.LastSignInMethodConfig{}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	linkResult, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{
		Token: tokenFromMail(t, mailer),
	})
	if err != nil || linkResult.LastSignInMethod != "magic-link" {
		t.Fatalf("magic link result = %+v, err = %v", linkResult, err)
	}
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	otpResult, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{
		Email: "user@example.com", Code: otpCodeFromMail(t, mailer),
	})
	if err != nil || otpResult.LastSignInMethod != "email-otp" {
		t.Fatalf("OTP result = %+v, err = %v", otpResult, err)
	}
}

func TestLastMethodPreservedBySecondFactor(t *testing.T) {
	client, totpStore, userID := twoFactorClient(t, func(cfg *signet.Config) {
		cfg.LastSignInMethod = &signet.LastSignInMethodConfig{}
	})
	ctx := context.Background()
	enabled, err := client.EnableTwoFactor(ctx, signet.EnableTwoFactorInput{
		UserID: userID, Password: "correct horse",
	})
	if err != nil {
		t.Fatalf("EnableTwoFactor: %v", err)
	}
	_ = totpStore
	result, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{
		Challenge: enabled.Challenge, Code: totpCode(t, enabled.TOTPURI, time.Now()),
	})
	if err != nil || result.LastSignInMethod != "password" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestLastMethodInJWTTokenPair(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.LastSignInMethod = &signet.LastSignInMethodConfig{}
	cfg.JWT = &signet.JWTConfig{Algorithm: "HS256", Key: []byte("jwt-key-123456789012345678901234")}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	pair, err := client.ExchangeToken(ctx, signet.TokenInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil || pair.LastSignInMethod != "password" {
		t.Fatalf("pair = %+v, err = %v", pair, err)
	}
}

func TestLastMethodForOAuthProvider(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.LastSignInMethod = &signet.LastSignInMethodConfig{}
	cfg.OAuth = &signet.OAuthConfig{
		Providers:        []signet.OAuthProvider{fakeOAuthProvider{name: "google"}},
		StateKey:         make([]byte, 32),
		RedirectBaseURL:  "https://api.example.com",
		AllowedRedirects: []string{"https://app.example.com/callback"},
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	started, err := client.OAuthStart(ctx, signet.OAuthStartInput{Provider: "google", Redirect: "https://app.example.com/callback"})
	if err != nil {
		t.Fatalf("OAuthStart: %v", err)
	}
	parsed, err := url.Parse(started.URL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	result, err := client.OAuthCallback(ctx, signet.OAuthCallbackInput{
		Code: "code", State: parsed.Query().Get("state"),
	})
	if err != nil || result.LastSignInMethod != "google" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestLastMethodRequiresCSRFKeys(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.JWTOnly = true
	cfg.LastSignInMethod = &signet.LastSignInMethodConfig{}
	if _, err := signet.New(cfg); err == nil {
		t.Fatal("JWT-only configs should not enable a browser cookie")
	}
}
