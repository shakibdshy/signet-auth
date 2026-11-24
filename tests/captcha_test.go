package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

type fakeCaptchaVerifier struct {
	calls  []string
	reject bool
	fail   error
}

func (v *fakeCaptchaVerifier) Verify(_ context.Context, token, remoteIP string) error {
	v.calls = append(v.calls, token+":"+remoteIP)
	if v.fail != nil {
		return v.fail
	}
	if v.reject || token != "good-token" {
		return signet.ErrCaptchaInvalid
	}
	return nil
}

func captchaClient(t *testing.T, verifier signet.CaptchaVerifier, configure func(*signet.Config)) *signet.Client {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.CaptchaVerifier = verifier
	if configure != nil {
		configure(&cfg)
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestCaptchaAcceptsAndRejectsSignUp(t *testing.T) {
	verifier := &fakeCaptchaVerifier{}
	client := captchaClient(t, verifier, nil)
	ctx := context.Background()
	_, err := client.SignUp(ctx, signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse",
		CaptchaToken: "good-token", CaptchaRemoteIP: "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("SignUp with good captcha: %v", err)
	}
	if len(verifier.calls) != 1 || verifier.calls[0] != "good-token:203.0.113.7" {
		t.Fatalf("calls = %+v", verifier.calls)
	}
	_, err = client.SignUp(ctx, signet.SignUpInput{
		Email: "other@example.com", Password: "correct horse", CaptchaToken: "bad-token",
	})
	if !errors.Is(err, signet.ErrCaptchaInvalid) {
		t.Fatalf("bad captcha error = %v", err)
	}
}

func TestCaptchaMissingTokenRejected(t *testing.T) {
	client := captchaClient(t, &fakeCaptchaVerifier{}, nil)
	_, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse",
	})
	if !errors.Is(err, signet.ErrCaptchaRequired) {
		t.Fatalf("error = %v, want ErrCaptchaRequired", err)
	}
}

func TestCaptchaProviderFailureRejected(t *testing.T) {
	verifier := &fakeCaptchaVerifier{fail: errors.New("provider down")}
	client := captchaClient(t, verifier, nil)
	_, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse", CaptchaToken: "good-token",
	})
	if !errors.Is(err, signet.ErrCaptchaUnavailable) {
		t.Fatalf("error = %v, want ErrCaptchaUnavailable", err)
	}
}

func TestCaptchaEndpointSelection(t *testing.T) {
	verifier := &fakeCaptchaVerifier{}
	client := captchaClient(t, verifier, func(cfg *signet.Config) {
		cfg.CaptchaEndpoints = []string{"signin"}
	})
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse",
	}); err != nil {
		t.Fatalf("signup should not require captcha: %v", err)
	}
	if len(verifier.calls) != 0 {
		t.Fatalf("verifier called for non-configured endpoint: %+v", verifier.calls)
	}
	if _, err := client.SignIn(ctx, signet.SignInInput{
		Email: "nobody@example.com", Password: "correct horse", CaptchaToken: "good-token",
	}); err == nil || errors.Is(err, signet.ErrCaptchaInvalid) {
		t.Fatalf("signin should verify captcha: %v", err)
	}
	if len(verifier.calls) != 1 {
		t.Fatalf("calls = %+v", verifier.calls)
	}
}

func TestCaptchaRejectsUnsupportedEndpoint(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.CaptchaVerifier = &fakeCaptchaVerifier{}
	cfg.CaptchaEndpoints = []string{"not-an-endpoint"}
	if _, err := signet.New(cfg); !errors.Is(err, signet.ErrInvalidCaptchaEndpoint) {
		t.Fatalf("error = %v, want ErrInvalidCaptchaEndpoint", err)
	}
}

func TestCaptchaRunsAfterRateLimit(t *testing.T) {
	verifier := &fakeCaptchaVerifier{}
	client := captchaClient(t, verifier, func(cfg *signet.Config) {
		cfg.RateLimiter = &testutil.Limiter{Allowed: false}
	})
	_, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse", CaptchaToken: "good-token",
	})
	if !errors.Is(err, signet.ErrRateLimited) {
		t.Fatalf("error = %v, want ErrRateLimited", err)
	}
	if len(verifier.calls) != 0 {
		t.Fatalf("captcha provider called before rate limit: %+v", verifier.calls)
	}
}

func TestCaptchaHTTPUsesHeaderAndClientIP(t *testing.T) {
	verifier := &fakeCaptchaVerifier{}
	client := captchaClient(t, verifier, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(`{"email":"user@example.com","password":"correct horse"}`))
	req.Header.Set("X-Captcha-Response", "good-token")
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	if len(verifier.calls) != 1 || !strings.HasPrefix(verifier.calls[0], "good-token:") ||
		strings.TrimPrefix(verifier.calls[0], "good-token:") == "" {
		t.Fatalf("calls = %+v", verifier.calls)
	}
}
