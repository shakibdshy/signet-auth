package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

type fakeBreachChecker struct {
	compromised map[string]bool
	fail        error
	checked     []string
}

func (c *fakeBreachChecker) Check(_ context.Context, password string) (bool, error) {
	c.checked = append(c.checked, password)
	if c.fail != nil {
		return false, c.fail
	}
	return c.compromised[password], nil
}

func breachClient(t *testing.T, checker signet.BreachChecker) (*signet.Client, *testutil.Mailer) {
	t.Helper()
	store := testutil.NewStore()
	mailer := testutil.NewMailer()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.BreachChecker = checker
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, mailer
}

func TestBreachCheckBlocksSignUp(t *testing.T) {
	checker := &fakeBreachChecker{compromised: map[string]bool{"bad-password": true}}
	client, _ := breachClient(t, checker)
	_, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "bad-password",
	})
	if !errors.Is(err, signet.ErrPasswordCompromised) {
		t.Fatalf("error = %v, want ErrPasswordCompromised", err)
	}
	if len(checker.checked) == 0 || checker.checked[0] != "bad-password" {
		t.Fatalf("checked = %+v", checker.checked)
	}
}

func TestBreachCheckBlocksPasswordChange(t *testing.T) {
	checker := &fakeBreachChecker{compromised: map[string]bool{"breached-new-password": true}}
	client, _ := breachClient(t, checker)
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	err = client.ChangePassword(ctx, signet.ChangePasswordInput{
		UserID: signUp.User.ID, CurrentPassword: "correct horse", NewPassword: "breached-new-password",
	})
	if !errors.Is(err, signet.ErrPasswordCompromised) {
		t.Fatalf("error = %v, want ErrPasswordCompromised", err)
	}
}

func TestBreachCheckBlocksPasswordReset(t *testing.T) {
	checker := &fakeBreachChecker{compromised: map[string]bool{"breached-reset-password": true}}
	client, mailer := breachClient(t, checker)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := client.SendPasswordReset(ctx, signet.SendPasswordResetInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}
	raw := tokenFromMail(t, mailer)
	err := client.ResetPassword(ctx, signet.ResetPasswordInput{
		Token: raw, NewPassword: "breached-reset-password",
	})
	if !errors.Is(err, signet.ErrPasswordCompromised) {
		t.Fatalf("error = %v, want ErrPasswordCompromised", err)
	}
}

func TestBreachProviderFailureFailsClosed(t *testing.T) {
	checker := &fakeBreachChecker{fail: errors.New("provider down")}
	client, _ := breachClient(t, checker)
	_, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse",
	})
	if err == nil || errors.Is(err, signet.ErrPasswordCompromised) {
		t.Fatalf("provider failure must reject with a provider error: %v", err)
	}
}
