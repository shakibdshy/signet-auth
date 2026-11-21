package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/testutil"
)

type denyLimiter struct{}

func (denyLimiter) Allow(context.Context, string) (bool, error) { return false, nil }

func TestPerEndpointRateLimit(t *testing.T) {
	store := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = &testutil.Mailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.RateLimitRules = map[string]core.RateLimitRule{"signin": {Limiter: denyLimiter{}}}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "rule@example.com", Password: "correct horse", Name: "Ada"}); err != nil {
		t.Fatalf("SignUp should be unlimited: %v", err)
	}
	if _, err := client.SignIn(ctx, signet.SignInInput{Email: "rule@example.com", Password: "correct horse"}); !errors.Is(err, signet.ErrRateLimited) {
		t.Fatalf("SignIn error = %v, want ErrRateLimited", err)
	}
}

func TestUnknownRateLimitRuleKeyRejected(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = &testutil.Mailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.RateLimitRules = map[string]core.RateLimitRule{"nonexistent": {}}
	if _, err := signet.New(cfg); !errors.Is(err, signet.ErrInvalidRateLimitRule) {
		t.Fatalf("error = %v, want ErrInvalidRateLimitRule", err)
	}
}

func TestPublishedEndpointNameRuleApplies(t *testing.T) {
	store := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = &testutil.Mailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.RateLimitRules = map[string]core.RateLimitRule{"change-password": {Limiter: denyLimiter{}}}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "rule2@example.com", Password: "correct horse", Name: "Ada"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := client.SignIn(ctx, signet.SignInInput{Email: "rule2@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	err = client.ChangePassword(ctx, signet.ChangePasswordInput{
		UserID: "unknown", CurrentPassword: "correct horse", NewPassword: "a much better password",
	})
	if !errors.Is(err, signet.ErrRateLimited) {
		t.Fatalf("ChangePassword error = %v, want ErrRateLimited", err)
	}
}
