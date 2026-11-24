package tests

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

func passwordlessClient(t *testing.T) (*signet.Client, *testutil.Store, *testutil.Mailer) {
	t.Helper()
	store := testutil.NewStore()
	mailer := testutil.NewMailer()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AppURL = "https://app.example.com"
	cfg.Passwordless = &signet.PasswordlessConfig{
		AllowedRedirects: []string{"https://app.example.com/welcome"},
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, store, mailer
}

func magicLinkTokenFromMail(t *testing.T, mailer *testutil.Mailer) string {
	t.Helper()
	if len(mailer.Messages) == 0 {
		t.Fatal("no magic-link email captured")
	}
	body := mailer.Messages[len(mailer.Messages)-1].TextBody
	i := strings.Index(body, "token=")
	if i < 0 {
		t.Fatalf("no token in email body: %q", body)
	}
	raw := body[i+len("token="):]
	if j := strings.IndexAny(raw, " \n&"); j >= 0 {
		raw = raw[:j]
	}
	return raw
}

func otpCodeFromMail(t *testing.T, mailer *testutil.Mailer) string {
	t.Helper()
	if len(mailer.Messages) == 0 {
		t.Fatal("no OTP email captured")
	}
	body := mailer.Messages[len(mailer.Messages)-1].TextBody
	match := regexp.MustCompile(`code is ([0-9]{6})`).FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("no six-digit code in email body: %q", body)
	}
	return match[1]
}

type countingLimiter struct {
	counts map[string]int
	limit  int
}

func (l *countingLimiter) Allow(_ context.Context, key string) (bool, error) {
	if l.counts == nil {
		l.counts = make(map[string]int)
	}
	l.counts[key]++
	return l.counts[key] <= l.limit, nil
}

func passwordlessClientWithConfig(t *testing.T, configure func(*signet.Config)) (*signet.Client, *testutil.Store, *testutil.Mailer) {
	t.Helper()
	store := testutil.NewStore()
	mailer := testutil.NewMailer()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AppURL = "https://app.example.com"
	cfg.Passwordless = &signet.PasswordlessConfig{
		AllowedRedirects: []string{"https://app.example.com/welcome"},
	}
	if configure != nil {
		configure(&cfg)
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, store, mailer
}

func TestEmailOTPSignsInExistingUser(t *testing.T) {
	client, store, mailer := passwordlessClient(t)
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse", Name: "Ada"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	if len(code) != 6 {
		t.Fatalf("code = %q", code)
	}
	if len(store.Tokens) != 1 || store.Tokens[0].Kind != signet.TokenEmailOTP || store.Tokens[0].Hash == code {
		t.Fatalf("tokens = %+v", store.Tokens)
	}
	result, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "user@example.com", Code: code})
	if err != nil {
		t.Fatalf("VerifyEmailOTP: %v", err)
	}
	if result.User.ID != signUp.User.ID || result.SessionToken == "" {
		t.Fatalf("result = %+v", result)
	}
}

func TestEmailOTPReplayAndResendRotation(t *testing.T) {
	client, store, mailer := passwordlessClient(t)
	ctx := context.Background()
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	first := otpCodeFromMail(t, mailer)
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("resend: %v", err)
	}
	second := otpCodeFromMail(t, mailer)
	if first == second && len(store.Tokens) > 1 {
		t.Fatal("expected a fresh code")
	}
	if len(store.Tokens) != 1 {
		t.Fatalf("tokens = %d, want 1 after rotation", len(store.Tokens))
	}
	if _, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "user@example.com", Code: first}); err == nil {
		t.Fatal("rotated code should be rejected")
	}
	if _, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "user@example.com", Code: second}); err != nil {
		t.Fatalf("current code: %v", err)
	}
	if _, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "user@example.com", Code: second}); err == nil {
		t.Fatal("consumed code should not be reusable")
	}
}

func TestEmailOTPExpiresWithClock(t *testing.T) {
	clock := &testutil.Clock{At: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	client, _, mailer := passwordlessClientWithConfig(t, func(cfg *signet.Config) { cfg.Clock = clock })
	ctx := context.Background()
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	clock.At = clock.At.Add(6 * time.Minute)
	if _, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "user@example.com", Code: code}); err == nil {
		t.Fatal("expired code should be rejected")
	}
}

func TestEmailOTPFailedGuessesAreThrottled(t *testing.T) {
	limiter := &countingLimiter{limit: 2}
	client, _, mailer := passwordlessClientWithConfig(t, func(cfg *signet.Config) { cfg.RateLimiter = limiter })
	ctx := context.Background()
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	wrong := "000000"
	if wrong == code {
		wrong = "999999"
	}
	var rejected int
	for i := 0; i < 4; i++ {
		if _, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "user@example.com", Code: wrong}); err != nil {
			rejected++
		}
	}
	if rejected < 2 {
		t.Fatalf("rejected = %d, expected repeated wrong guesses to be throttled", rejected)
	}
	if _, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "user@example.com", Code: code}); err == nil {
		t.Fatal("correct code should not bypass the throttle")
	}
}

func TestEmailOTPAutoCreatesVerifiedUser(t *testing.T) {
	client, store, mailer := passwordlessClient(t)
	ctx := context.Background()
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "new@example.com", Name: "Grace"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	result, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "new@example.com", Code: code})
	if err != nil {
		t.Fatalf("VerifyEmailOTP: %v", err)
	}
	user := store.Users[result.User.ID]
	// The code carries no embedded data, so an auto-created User has no name.
	if user == nil || user.Email != "new@example.com" || !user.EmailVerified || user.Name != "" {
		t.Fatalf("user = %+v", user)
	}
}

func TestEmailOTPSendIsSilentWhenSignUpDisabled(t *testing.T) {
	client, store, mailer := passwordlessClientWithConfig(t, func(cfg *signet.Config) {
		cfg.Passwordless = &signet.PasswordlessConfig{AllowSignUp: testutil.BoolPtr(false)}
	})
	if err := client.SendEmailOTP(context.Background(), signet.SendEmailOTPInput{Email: "new@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	if len(mailer.Messages) != 0 || len(store.Tokens) != 0 {
		t.Fatalf("messages = %+v tokens = %+v", mailer.Messages, store.Tokens)
	}
}

func TestEmailOTPHTTPFlowSetsCookie(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	handler := client.Handler()
	body := `{"email":"user@example.com","code":"` + code + `"}`
	req := httptest.NewRequest(http.MethodPost, "/verify-otp", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	var found bool
	for _, cookie := range rr.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, "signet_session") || strings.HasPrefix(cookie.Name, "__Host-signet_session") {
			found = true
		}
	}
	if !found {
		t.Fatalf("session cookie not set: %+v", rr.Result().Cookies())
	}
}

func TestPasswordlessSendEndpointsAreRateLimited(t *testing.T) {
	for _, endpoint := range []string{"/send-magic-link", "/send-otp"} {
		t.Run(endpoint, func(t *testing.T) {
			client, _, _ := passwordlessClientWithConfig(t, func(cfg *signet.Config) {
				cfg.RateLimiter = &testutil.Limiter{Allowed: false}
			})
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{"email":"user@example.com"}`))
			client.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestPasswordlessVerifyEndpointsAreRateLimited(t *testing.T) {
	client, _, _ := passwordlessClientWithConfig(t, func(cfg *signet.Config) {
		cfg.RateLimiter = &testutil.Limiter{Allowed: false}
	})
	for _, tc := range []struct {
		path, body string
	}{
		{"/verify-magic-link?token=x", ""},
		{"/verify-otp", `{"email":"user@example.com","code":"123456"}`},
	} {
		t.Run(tc.path, func(t *testing.T) {
			method := http.MethodPost
			if tc.body == "" {
				method = http.MethodGet
			}
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(method, tc.path, strings.NewReader(tc.body))
			client.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestMagicLinkExpiresWithClock(t *testing.T) {
	clock := &testutil.Clock{At: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	client, _, mailer := passwordlessClientWithConfig(t, func(cfg *signet.Config) { cfg.Clock = clock })
	ctx := context.Background()
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	raw := magicLinkTokenFromMail(t, mailer)
	clock.At = clock.At.Add(6 * time.Minute)
	if _, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: raw}); err == nil {
		t.Fatal("expired magic link should be rejected")
	}
}

func TestPasswordlessDefaultsHoldForHandBuiltConfig(t *testing.T) {
	clock := &testutil.Clock{At: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	client, _, mailer := passwordlessClientWithConfig(t, func(cfg *signet.Config) {
		cfg.Clock = clock
		cfg.Passwordless = &signet.PasswordlessConfig{}
	})
	ctx := context.Background()
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	clock.At = clock.At.Add(4 * time.Minute)
	if _, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "user@example.com", Code: code}); err != nil {
		t.Fatalf("code within the default TTL should be accepted: %v", err)
	}
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("second SendEmailOTP: %v", err)
	}
	second := otpCodeFromMail(t, mailer)
	clock.At = clock.At.Add(6 * time.Minute)
	if _, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "user@example.com", Code: second}); err == nil {
		t.Fatal("code past the default TTL should be rejected")
	}
}

func TestEmailOTPWrongEmailReturnsInvalidCode(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	_, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{
		Email: "other@example.com", Code: code,
	})
	if !errors.Is(err, signet.ErrInvalidOTP) {
		t.Fatalf("error = %v, want ErrInvalidOTP", err)
	}
}

func TestEmailOTPConsumedCodeReportsAlreadyUsed(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	if _, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{
		Email: "user@example.com", Code: code,
	}); err != nil {
		t.Fatalf("first VerifyEmailOTP: %v", err)
	}
	_, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{
		Email: "user@example.com", Code: code,
	})
	if !errors.Is(err, signet.ErrOTPAlreadyUsed) {
		t.Fatalf("error = %v, want ErrOTPAlreadyUsed", err)
	}
}

func TestEmailOTPErrorWireCodes(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	handler := client.Handler()
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/verify-otp", strings.NewReader(body))
		handler.ServeHTTP(rr, req)
		return rr
	}
	wrong := post(`{"email":"other@example.com","code":"` + code + `"}`)
	if wrong.Code != http.StatusUnauthorized || !strings.Contains(wrong.Body.String(), `"error":"invalid_code"`) {
		t.Fatalf("wrong email: status = %d body = %s", wrong.Code, wrong.Body.String())
	}
	if _, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "user@example.com", Code: code}); err != nil {
		t.Fatalf("VerifyEmailOTP: %v", err)
	}
	replay := post(`{"email":"user@example.com","code":"` + code + `"}`)
	if replay.Code != http.StatusUnauthorized || !strings.Contains(replay.Body.String(), `"error":"code_already_used"`) {
		t.Fatalf("replay: status = %d body = %s", replay.Code, replay.Body.String())
	}
}

func TestMagicLinkReplayReportsAlreadyUsed(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	raw := magicLinkTokenFromMail(t, mailer)
	if _, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: raw}); err != nil {
		t.Fatalf("first VerifyMagicLink: %v", err)
	}
	_, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: raw})
	if !errors.Is(err, signet.ErrMagicLinkAlreadyUsed) {
		t.Fatalf("error = %v, want ErrMagicLinkAlreadyUsed", err)
	}
}

func TestMagicLinkMalformedOrExpiredReportsInvalidLink(t *testing.T) {
	client, _, _ := passwordlessClient(t)
	ctx := context.Background()
	if _, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: "garbage"}); !errors.Is(err, signet.ErrInvalidMagicLink) {
		t.Fatalf("malformed error = %v, want ErrInvalidMagicLink", err)
	}
	clock := &testutil.Clock{At: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	expiring, _, expiringMailer := passwordlessClientWithConfig(t, func(cfg *signet.Config) { cfg.Clock = clock })
	if err := expiring.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	raw := magicLinkTokenFromMail(t, expiringMailer)
	clock.At = clock.At.Add(6 * time.Minute)
	if _, err := expiring.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: raw}); !errors.Is(err, signet.ErrInvalidMagicLink) {
		t.Fatalf("expired error = %v, want ErrInvalidMagicLink", err)
	}
}

func TestMagicLinkErrorWireCodes(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	raw := magicLinkTokenFromMail(t, mailer)
	handler := client.Handler()
	get := func(token string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/verify-magic-link?token="+url.QueryEscape(token), nil)
		handler.ServeHTTP(rr, req)
		return rr
	}
	malformed := get("garbage")
	if malformed.Code != http.StatusUnauthorized || !strings.Contains(malformed.Body.String(), `"error":"invalid_link"`) {
		t.Fatalf("malformed: status = %d body = %s", malformed.Code, malformed.Body.String())
	}
	if _, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: raw}); err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	replay := get(raw)
	if replay.Code != http.StatusUnauthorized || !strings.Contains(replay.Body.String(), `"error":"link_already_used"`) {
		t.Fatalf("replay: status = %d body = %s", replay.Code, replay.Body.String())
	}
}

func TestPasswordlessConfigValidationRejectsNegativeTTL(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Passwordless = &signet.PasswordlessConfig{OTPTTL: -time.Second}
	if _, err := signet.New(cfg); !errors.Is(err, signet.ErrInvalidPasswordlessConfig) {
		t.Fatalf("error = %v, want ErrInvalidPasswordlessConfig", err)
	}
}

func TestPasswordlessErrorsUseStandardSentinels(t *testing.T) {
	client, _, _ := passwordlessClient(t)
	ctx := context.Background()
	if _, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: "garbage"}); !errors.Is(err, signet.ErrInvalidMagicLink) {
		t.Fatalf("magic link error = %v", err)
	}
	if _, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "user@example.com", Code: "abc"}); !errors.Is(err, signet.ErrInvalidOTP) {
		t.Fatalf("otp error = %v", err)
	}
	denied, _, _ := passwordlessClientWithConfig(t, func(cfg *signet.Config) {
		cfg.RateLimiter = &testutil.Limiter{Allowed: false}
	})
	if err := denied.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); !errors.Is(err, signet.ErrRateLimited) {
		t.Fatalf("rate-limit error = %v", err)
	}
}

func TestPasswordlessFlowsDoNotLogSecrets(t *testing.T) {
	var logs strings.Builder
	client, _, mailer := passwordlessClientWithConfig(t, func(cfg *signet.Config) {
		cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	})
	ctx := context.Background()
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	raw := magicLinkTokenFromMail(t, mailer)
	if _, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: raw}); err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	if _, err := client.VerifyEmailOTP(ctx, signet.VerifyEmailOTPInput{Email: "user@example.com", Code: code}); err != nil {
		t.Fatalf("VerifyEmailOTP: %v", err)
	}
	if strings.Contains(logs.String(), raw) || strings.Contains(logs.String(), code) {
		t.Fatalf("secrets appeared in logs: %s", logs.String())
	}
}

func TestMagicLinkEmailUsesConfiguredPathPrefix(t *testing.T) {
	client, _, mailer := passwordlessClientWithConfig(t, func(cfg *signet.Config) {
		cfg.PathPrefix = "/auth"
	})
	if err := client.SendMagicLink(context.Background(), signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	if len(mailer.Messages) == 0 {
		t.Fatal("no magic-link email captured")
	}
	body := mailer.Messages[0].TextBody
	if !strings.Contains(body, "http://localhost:8080/auth/verify-magic-link?token=") &&
		!strings.Contains(body, "https://app.example.com/auth/verify-magic-link?token=") {
		t.Fatalf("email link does not include the configured path prefix: %q", body)
	}
}

func TestMagicLinkSignsInExistingUser(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse", Name: "Ada"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{
		Email: "user@example.com", CallbackURL: "https://app.example.com/welcome",
	}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	if len(mailer.Messages) != 1 || mailer.Messages[0].To != "user@example.com" {
		t.Fatalf("messages = %+v", mailer.Messages)
	}
	raw := magicLinkTokenFromMail(t, mailer)

	result, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: raw})
	if err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	if result.User.ID != signUp.User.ID || result.SessionToken == "" {
		t.Fatalf("result = %+v", result)
	}
	sessions, err := client.ListSessions(ctx, signet.ListSessionsInput{UserID: signUp.User.ID})
	if err != nil || len(sessions.Sessions) != 1 {
		t.Fatalf("sessions = %+v, err = %v", sessions, err)
	}
}

func TestMagicLinkAutoCreatesVerifiedUser(t *testing.T) {
	client, store, mailer := passwordlessClient(t)
	ctx := context.Background()
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "new@example.com", Name: "Grace"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	raw := magicLinkTokenFromMail(t, mailer)
	result, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: raw})
	if err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	user := store.Users[result.User.ID]
	if user == nil || user.Email != "new@example.com" || !user.EmailVerified || user.Name != "Grace" {
		t.Fatalf("user = %+v", user)
	}
	if accounts, _ := store.AccountsForUser(ctx, user.ID); len(accounts) != 0 {
		t.Fatalf("passwordless User should have no credential Account: %+v", accounts)
	}
}

func TestMagicLinkSendIsSilentWhenSignUpDisabled(t *testing.T) {
	_, store, mailer := passwordlessClient(t)
	// A fresh client is needed because New applies defaults at construction.
	config := testutil.NewConfig()
	config.Store = store
	config.Mailer = mailer
	config.RateLimiter = &testutil.Limiter{Allowed: true}
	config.AppURL = "https://app.example.com"
	config.Passwordless = &signet.PasswordlessConfig{AllowSignUp: testutil.BoolPtr(false)}
	disabled, err := signet.New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := disabled.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "new@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	if len(mailer.Messages) != 0 || len(store.Tokens) != 0 {
		t.Fatalf("messages = %+v tokens = %+v", mailer.Messages, store.Tokens)
	}
}

func TestMagicLinkRejectsOffOriginCallback(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{
		Email: "user@example.com", CallbackURL: "https://evil.example.com/steal",
	}); err == nil {
		t.Fatal("off-origin callback should be rejected")
	}
	if len(mailer.Messages) != 0 {
		t.Fatalf("no mail should be sent: %+v", mailer.Messages)
	}
}

func TestMagicLinkHTTPRedirectsWithEmbeddedCallbackOnly(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	callback := "https://app.example.com/welcome"
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com", CallbackURL: callback}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	raw := magicLinkTokenFromMail(t, mailer)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/verify-magic-link?token="+url.QueryEscape(raw), nil)
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != callback {
		t.Fatalf("status = %d location = %q body = %s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
}

func TestMagicLinkRejectsMismatchedCallbackAtVerification(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{
		Email: "user@example.com", CallbackURL: "https://app.example.com/welcome",
	}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	raw := magicLinkTokenFromMail(t, mailer)
	_, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{
		Token: raw, CallbackURL: "https://app.example.com/other",
	})
	if !errors.Is(err, signet.ErrOAuthRedirectNotAllowed) {
		t.Fatalf("error = %v, want ErrOAuthRedirectNotAllowed", err)
	}
}

func TestMagicLinkRejectsUnlistedSameOriginCallback(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{
		Email: "user@example.com", CallbackURL: "https://app.example.com/attacker",
	}); err == nil {
		t.Fatal("same-origin but unlisted callback should be rejected")
	}
	if len(mailer.Messages) != 0 {
		t.Fatalf("no mail should be sent: %+v", mailer.Messages)
	}
}

func TestMagicLinkResendRotatesProof(t *testing.T) {
	client, store, mailer := passwordlessClient(t)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	first := magicLinkTokenFromMail(t, mailer)
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("second SendMagicLink: %v", err)
	}
	second := magicLinkTokenFromMail(t, mailer)
	if first == second {
		t.Fatal("resend should issue a new proof")
	}
	if len(store.Tokens) != 1 {
		t.Fatalf("tokens = %d, want 1 after rotation", len(store.Tokens))
	}
	if _, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: first}); err == nil {
		t.Fatal("rotated proof should be rejected")
	}
	if _, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: second}); err != nil {
		t.Fatalf("VerifyMagicLink with current proof: %v", err)
	}
}

func TestMagicLinkHTTPRedirectsToCallback(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	callback := "https://app.example.com/welcome"
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com", CallbackURL: callback}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	raw := magicLinkTokenFromMail(t, mailer)
	handler := client.Handler()
	req := httptest.NewRequest(http.MethodGet, "/verify-magic-link?token="+url.QueryEscape(raw)+"&callback_url="+url.QueryEscape(callback), nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != callback {
		t.Fatalf("status = %d location = %q body = %s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
}

func TestMagicLinkVerificationIsSingleUse(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse", Name: "Ada"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	raw := magicLinkTokenFromMail(t, mailer)
	if _, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: raw}); err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	if _, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: raw}); err == nil {
		t.Fatal("replaying a consumed magic link should fail")
	}
}

func TestMagicLinkHTTPFlowSetsCookie(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse", Name: "Ada"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	raw := magicLinkTokenFromMail(t, mailer)

	handler := client.Handler()
	req := httptest.NewRequest(http.MethodGet, "/verify-magic-link?token="+url.QueryEscape(raw), nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"session_token"`) || !strings.Contains(rr.Body.String(), `"user"`) {
		t.Fatalf("session JSON not returned: %s", rr.Body.String())
	}
	var found bool
	for _, cookie := range rr.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, "signet_session") || strings.HasPrefix(cookie.Name, "__Host-signet_session") {
			found = true
		}
	}
	if !found {
		t.Fatalf("session cookie not set: %+v", rr.Result().Cookies())
	}
}
