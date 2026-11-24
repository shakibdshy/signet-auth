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

type autoSignInAuditSink struct{ events []signet.AuditEvent }

func (s *autoSignInAuditSink) Record(_ context.Context, event signet.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func autoSignInClient(t *testing.T, afterSignUp, afterVerification bool, requireVerified *bool, hookCalls *int, sink signet.AuditSink) (*signet.Client, *testutil.Mailer) {
	t.Helper()
	store := testutil.NewStore()
	mailer := testutil.NewMailer()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AppURL = "https://app.example.com"
	cfg.RequireVerifiedEmail = requireVerified
	cfg.SendVerificationOnSignUp = testutil.BoolPtr(true)
	cfg.LastSignInMethod = &signet.LastSignInMethodConfig{}
	cfg.AutoSignIn = &signet.AutoSignInConfig{
		AfterSignUp: afterSignUp, AfterVerification: afterVerification,
	}
	cfg.OnSignIn = func(context.Context, *signet.User) { *hookCalls++ }
	cfg.AuditSink = sink
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, mailer
}

func verificationToken(t *testing.T, mailer *testutil.Mailer) string {
	t.Helper()
	if len(mailer.Messages) == 0 {
		t.Fatal("no verification email")
	}
	body := mailer.Messages[len(mailer.Messages)-1].TextBody
	i := strings.Index(body, "token=")
	if i < 0 {
		t.Fatalf("no token in email: %q", body)
	}
	raw := body[i+len("token="):]
	if j := strings.IndexAny(raw, " \n&"); j >= 0 {
		raw = raw[:j]
	}
	return raw
}

func TestAutomaticSignInDisabledByDefault(t *testing.T) {
	client, _ := autoSignInClient(t, false, false, nil, new(int), nil)
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if signUp.SessionToken != "" {
		t.Fatalf("unexpected sign-up session: %q", signUp.SessionToken)
	}
}

func TestAutomaticSignInAfterVerification(t *testing.T) {
	calls := 0
	sink := &autoSignInAuditSink{}
	client, mailer := autoSignInClient(t, false, true, nil, &calls, sink)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.VerifyEmailAndSignIn(ctx, signet.VerifyEmailInput{Token: verificationToken(t, mailer)})
	if err != nil {
		t.Fatalf("VerifyEmailAndSignIn: %v", err)
	}
	if result.SessionToken == "" || result.User == nil {
		t.Fatalf("result = %+v", result)
	}
	if err := client.VerifyFreshSession(ctx, result.SessionToken); err != nil {
		t.Fatalf("session not valid: %v", err)
	}
	if calls != 1 {
		t.Fatalf("OnSignIn calls = %d", calls)
	}
	found := false
	for _, event := range sink.events {
		if event.Name == "sign_in_success" && event.Metadata["method"] == "email" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no sign-in audit event: %+v", sink.events)
	}
	if _, err := client.VerifyEmailAndSignIn(ctx, signet.VerifyEmailInput{Token: verificationToken(t, mailer)}); err == nil {
		t.Fatal("verification token replay accepted")
	}
}

func TestAutomaticSignInAfterVerificationDisabled(t *testing.T) {
	client, mailer := autoSignInClient(t, false, false, nil, new(int), nil)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.VerifyEmailAndSignIn(ctx, signet.VerifyEmailInput{Token: verificationToken(t, mailer)})
	if err != nil || result.SessionToken != "" {
		t.Fatalf("result = %+v err = %v", result, err)
	}
}

func TestAutomaticSignInAfterSignUpWhenVerificationNotRequired(t *testing.T) {
	no := false
	calls := 0
	client, _ := autoSignInClient(t, true, false, &no, &calls, nil)
	result, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse",
	})
	if err != nil || result.SessionToken == "" {
		t.Fatalf("result = %+v err = %v", result, err)
	}
	if err := client.VerifyFreshSession(context.Background(), result.SessionToken); err != nil {
		t.Fatalf("session not valid: %v", err)
	}
	if calls != 1 {
		t.Fatalf("OnSignIn calls = %d", calls)
	}
}

func TestAutomaticSignInAfterSignUpBlockedForUnverified(t *testing.T) {
	calls := 0
	client, _ := autoSignInClient(t, true, false, nil, &calls, nil)
	result, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse",
	})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if result.SessionToken != "" {
		t.Fatalf("unverified sign-up issued session: %q", result.SessionToken)
	}
	if calls != 0 {
		t.Fatalf("OnSignIn calls = %d", calls)
	}
}

func TestAutomaticSignInHTTPEndpoints(t *testing.T) {
	no := false
	calls := 0
	client, mailer := autoSignInClient(t, true, true, &no, &calls, nil)
	ctx := context.Background()
	signUp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(`{"email":"web@example.com","password":"correct horse"}`))
	client.Handler().ServeHTTP(signUp, req)
	if signUp.Code != http.StatusCreated {
		t.Fatalf("signup status = %d body = %s", signUp.Code, signUp.Body.String())
	}
	if !strings.Contains(signUp.Body.String(), "session_token") {
		t.Fatalf("no session token: %s", signUp.Body.String())
	}
	var hasSessionCookie bool
	for _, cookie := range signUp.Result().Cookies() {
		if strings.HasSuffix(cookie.Name, "signet_session") {
			hasSessionCookie = true
		}
	}
	if !hasSessionCookie {
		t.Fatalf("no session cookie: %+v", signUp.Result().Cookies())
	}
	verify := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/verify-email", strings.NewReader(`{"token":"`+verificationToken(t, mailer)+`"}`))
	client.Handler().ServeHTTP(verify, req)
	if verify.Code != http.StatusOK || !strings.Contains(verify.Body.String(), "session_token") {
		t.Fatalf("verify status = %d body = %s", verify.Code, verify.Body.String())
	}
	if calls != 2 {
		t.Fatalf("OnSignIn calls = %d", calls)
	}
	_ = ctx
}

type countingLimiterAuto struct{ calls int }

func (l *countingLimiterAuto) Allow(_ context.Context, _ string) (bool, error) {
	l.calls++
	return true, nil
}

func TestAutomaticSignInDoesNotDuplicateRateLimit(t *testing.T) {
	store := testutil.NewStore()
	mailer := testutil.NewMailer()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	limiter := &countingLimiterAuto{}
	cfg.RateLimiter = limiter
	cfg.AppURL = "https://app.example.com"
	cfg.LastSignInMethod = &signet.LastSignInMethodConfig{}
	cfg.SendVerificationOnSignUp = testutil.BoolPtr(true)
	cfg.AutoSignIn = &signet.AutoSignInConfig{AfterVerification: true}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	_, err = client.SignUp(ctx, signet.SignUpInput{Email: "rate@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	before := limiter.calls
	if _, err := client.VerifyEmailAndSignIn(ctx, signet.VerifyEmailInput{Token: verificationToken(t, mailer)}); err != nil {
		t.Fatalf("VerifyEmailAndSignIn: %v", err)
	}
	if limiter.calls != before+1 {
		t.Fatalf("limiter calls = %d, want %d", limiter.calls, before+1)
	}
}

func TestAutomaticSignInLastMethodCookie(t *testing.T) {
	no := false
	client, mailer := autoSignInClient(t, false, true, &no, new(int), nil)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "last@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/verify-email",
		strings.NewReader(`{"token":"`+verificationToken(t, mailer)+`"}`))
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	found := false
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "signet_last_method" && cookie.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no last-method cookie: %+v", rr.Result().Cookies())
	}
}
