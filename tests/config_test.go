package tests

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

func completeConfig() signet.Config {
	cfg := signet.DefaultConfig()
	cfg.CSRFKey = make([]byte, 32)
	cfg.Store = &fakeStore{}
	cfg.Mailer = fakeMailer{}
	cfg.PasswordHasher = fakePasswordHasher{}
	cfg.RateLimiter = fakeRateLimiter{}
	return cfg
}

func TestDefaultConfig(t *testing.T) {
	cfg := signet.DefaultConfig()
	if !cfg.Cookie.Secure || !cfg.Cookie.HttpOnly {
		t.Error("cookies must be Secure and HttpOnly by default")
	}
	if cfg.Cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cfg.Cookie.SameSite)
	}
	if cfg.Cookie.Name == "" || cfg.Cookie.Path != "/" {
		t.Errorf("cookie name/path = %q/%q, want a name and /", cfg.Cookie.Name, cfg.Cookie.Path)
	}
	if cfg.Session.IdleTimeout != 30*time.Minute || cfg.Session.AbsoluteTimeout != 24*time.Hour {
		t.Errorf("session timeouts = %v/%v, want 30m/24h", cfg.Session.IdleTimeout, cfg.Session.AbsoluteTimeout)
	}
	if cfg.Password.MinLength != 8 || cfg.Password.MaxLength != 128 {
		t.Errorf("password bounds = %d/%d, want 8/128", cfg.Password.MinLength, cfg.Password.MaxLength)
	}
	if cfg.Clock == nil || cfg.Logger == nil {
		t.Error("Clock and Logger must have defaults")
	}
	if cfg.PathPrefix != "/" {
		t.Errorf("PathPrefix = %q, want /", cfg.PathPrefix)
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*signet.Config)
		want   error
	}{
		{"store", func(c *signet.Config) { c.Store = nil }, signet.ErrMissingStore},
		{"mailer", func(c *signet.Config) { c.Mailer = nil }, signet.ErrMissingMailer},
		{"limiter", func(c *signet.Config) { c.RateLimiter = nil }, signet.ErrMissingRateLimiter},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := completeConfig()
			tt.mutate(&cfg)
			if _, err := signet.New(cfg); !errors.Is(err, tt.want) {
				t.Fatalf("New() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestNewRejectsInsecureCookies(t *testing.T) {
	cfg := completeConfig()
	cfg.Cookie.Secure = false
	if _, err := signet.New(cfg); !errors.Is(err, signet.ErrInsecureConfig) {
		t.Fatalf("New() error = %v, want ErrInsecureConfig", err)
	}
}

func TestNewRejectsNonHTTPOnlyCookies(t *testing.T) {
	cfg := completeConfig()
	cfg.Cookie.HttpOnly = false
	if _, err := signet.New(cfg); !errors.Is(err, signet.ErrInsecureConfig) {
		t.Fatalf("New() error = %v, want ErrInsecureConfig", err)
	}
}

func TestNewAllowsInsecureCookiesWhenOptedIn(t *testing.T) {
	cfg := completeConfig()
	cfg.Cookie.Secure = false
	cfg.InsecureAllowHTTPCookies = true
	var logs bytes.Buffer
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	if _, err := signet.New(cfg); err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	if !strings.Contains(logs.String(), "insecure") {
		t.Errorf("expected a warning about insecure cookies, got %q", logs.String())
	}
}

func TestNewSuppliesDefaultHasher(t *testing.T) {
	cfg := completeConfig()
	cfg.PasswordHasher = nil
	if _, err := signet.New(cfg); err != nil {
		t.Fatalf("New() error = %v, want nil with the default hasher", err)
	}
}

func TestNewRequiresCSRFKeyForCookieSessions(t *testing.T) {
	cfg := completeConfig()
	cfg.CSRFKey = nil
	if _, err := signet.New(cfg); !errors.Is(err, signet.ErrInvalidCSRFConfig) {
		t.Fatalf("New error = %v, want ErrInvalidCSRFConfig", err)
	}
}

func TestJWTOnlyDoesNotRequireCSRFKey(t *testing.T) {
	cfg := completeConfig()
	cfg.CSRFKey = nil
	cfg.JWTOnly = true
	cfg.JWT = &signet.JWTConfig{Algorithm: "HS256", Key: make([]byte, 32)}
	if _, err := signet.New(cfg); err != nil {
		t.Fatalf("New error = %v, want nil for a JWT-only setup", err)
	}
}

func TestNewSucceedsWithCompleteConfig(t *testing.T) {
	cfg := completeConfig()
	cfg.Clock = nil
	cfg.Logger = nil
	cfg.OnSignUp = func(context.Context, *signet.User) {}
	cfg.OnSignIn = func(context.Context, *signet.User) {}
	if _, err := signet.New(cfg); err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
}

func TestEmailVerificationCanBeDisabled(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	yes := true
	cfg.RequireVerifiedEmail = &yes
	cfg.SendVerificationOnSignUp = &yes
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "unverified@example.com", Password: "correct horse",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	_, err = client.SignIn(context.Background(), signet.SignInInput{
		Email: "unverified@example.com", Password: "correct horse",
	})
	if err == nil {
		t.Fatal("expected email_not_verified with default config, got nil")
	}
	if !errors.Is(err, signet.ErrEmailNotVerified) {
		t.Fatalf("error = %v, want ErrEmailNotVerified", err)
	}
}

func TestEmailVerificationCanBeDisabledExplicitly(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	off := false
	cfg.RequireVerifiedEmail = &off
	cfg.SendVerificationOnSignUp = &off
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "unverified@example.com", Password: "correct horse",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(context.Background(), signet.SignInInput{
		Email: "unverified@example.com", Password: "correct horse",
	})
	if err != nil {
		t.Fatalf("SignIn with verification disabled: %v", err)
	}
	if result.User.EmailVerified {
		t.Error("User should not be verified when verification is disabled")
	}
}
