package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

func patternClient(t *testing.T, patterns []string, configure func(*signet.Config)) *signet.Client {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AppURL = "https://app.example.com"
	cfg.OAuth = &signet.OAuthConfig{
		Providers: []signet.OAuthProvider{fakeOAuthProvider{name: "google"}},
		StateKey:  make([]byte, 32),
	}
	cfg.AllowedRedirectPatterns = patterns
	if configure != nil {
		configure(&cfg)
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestRedirectPatternAllowsMagicLinkSubdomain(t *testing.T) {
	client := patternClient(t, []string{"https://*.example.com"}, nil)
	ctx := context.Background()
	callback := "https://welcome.example.com/done"
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{
		Email: "user@example.com", CallbackURL: callback,
	}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
}

func TestRedirectPatternRejectsMagicLinkLookalike(t *testing.T) {
	client := patternClient(t, []string{"https://*.example.com"}, nil)
	err := client.SendMagicLink(context.Background(), signet.SendMagicLinkInput{
		Email: "user@example.com", CallbackURL: "https://example.com.evil.test/done",
	})
	if !errors.Is(err, signet.ErrOAuthRedirectNotAllowed) {
		t.Fatalf("error = %v, want ErrOAuthRedirectNotAllowed", err)
	}
}

func TestRedirectPatternAllowsOAuthSubdomain(t *testing.T) {
	client := patternClient(t, []string{"https://*.example.com"}, nil)
	_, err := client.OAuthStart(context.Background(), signet.OAuthStartInput{
		Provider: "google", Redirect: "https://welcome.example.com/callback",
	})
	if err != nil {
		t.Fatalf("OAuthStart: %v", err)
	}
}

func TestRedirectPatternInvalidConfigurationRejected(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.OAuth = &signet.OAuthConfig{
		Providers: []signet.OAuthProvider{fakeOAuthProvider{name: "google"}},
		StateKey:  make([]byte, 32),
	}
	cfg.AllowedRedirectPatterns = []string{"http://*.example.com"}
	if _, err := signet.New(cfg); !errors.Is(err, signet.ErrInvalidRedirectPattern) {
		t.Fatalf("error = %v, want ErrInvalidRedirectPattern", err)
	}
}
