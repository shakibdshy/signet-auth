package tests

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

type fakeWindowLimiter struct {
	calls      int
	allow      bool
	lastLimit  int
	lastWindow time.Duration
}

func (l *fakeWindowLimiter) Allow(_ context.Context, _ string, limit int, window time.Duration) (bool, error) {
	l.calls++
	l.lastLimit = limit
	l.lastWindow = window
	return l.allow, nil
}

type fakeAuditQueryStore struct {
	events []signet.AuditEvent
}

func (s *fakeAuditQueryStore) Record(_ context.Context, event signet.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}
func (s *fakeAuditQueryStore) Query(_ context.Context, in signet.AuditQueryInput) ([]*signet.AuditEvent, error) {
	out := make([]*signet.AuditEvent, 0, len(s.events))
	for _, event := range s.events {
		if in.Name != "" && event.Name != in.Name {
			continue
		}
		if in.Outcome != "" && event.Outcome != in.Outcome {
			continue
		}
		clone := event
		out = append(out, &clone)
		if len(out) >= in.Limit {
			break
		}
	}
	return out, nil
}

func controlsClient(t *testing.T, window signet.WindowLimiter, sink *fakeAuditQueryStore) (*signet.Client, string) {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.WindowLimiter = window
	if sink != nil {
		cfg.AuditSink = sink
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	return client, signUp.User.ID + "|" + signIn.SessionToken
}

func splitSession(value string) (string, string) {
	for i := 0; i < len(value); i++ {
		if value[i] == '|' {
			return value[:i], value[i+1:]
		}
	}
	return "", ""
}

func TestUpdateUser(t *testing.T) {
	client, packed := controlsClient(t, nil, nil)
	userID, token := splitSession(packed)
	ctx := context.Background()
	updated, err := client.UpdateUser(ctx, signet.UpdateUserInput{
		UserID: userID, SessionToken: token, Name: "Ada",
	})
	if err != nil || updated.Name != "Ada" {
		t.Fatalf("updated = %+v err = %v", updated, err)
	}
	if _, err := client.UpdateUser(ctx, signet.UpdateUserInput{
		UserID: "other-user", SessionToken: token, Name: "Mallory",
	}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("cross-user error = %v", err)
	}
	if _, err := client.UpdateUser(ctx, signet.UpdateUserInput{
		UserID: userID, SessionToken: "stale", Name: "Mallory",
	}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("stale error = %v", err)
	}
}

func TestSetAndVerifyPassword(t *testing.T) {
	client, packed := controlsClient(t, nil, nil)
	userID, token := splitSession(packed)
	ctx := context.Background()
	if err := client.SetPassword(ctx, signet.SetPasswordInput{
		UserID: userID, SessionToken: token, NewPassword: "new password",
	}); !errors.Is(err, signet.ErrInvalidCredentials) {
		t.Fatalf("existing credential should be denied: %v", err)
	}
	ok, err := client.VerifyPassword(ctx, signet.VerifyPasswordInput{UserID: userID, Password: "correct horse"})
	if err != nil || !ok {
		t.Fatalf("verify = %v err = %v", ok, err)
	}
	ok, err = client.VerifyPassword(ctx, signet.VerifyPasswordInput{UserID: "unknown", Password: "x"})
	if err != nil || ok {
		t.Fatalf("unknown verify = %v err = %v", ok, err)
	}
}

func TestWindowLimiterUsed(t *testing.T) {
	window := &fakeWindowLimiter{allow: true}
	_, _ = controlsClient(t, window, nil)
	if window.calls == 0 {
		t.Fatal("window limiter never called during sign-up/sign-in")
	}
}

func TestWindowLimiterBlocks(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.WindowLimiter = &fakeWindowLimiter{allow: false}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.SignUp(context.Background(), signet.SignUpInput{Email: "x@example.com", Password: "correct horse"})
	if !errors.Is(err, signet.ErrRateLimited) {
		t.Fatalf("rate-limit error = %v", err)
	}
}

func TestQueryAudit(t *testing.T) {
	sink := &fakeAuditQueryStore{}
	client, packed := controlsClient(t, nil, sink)
	userID, token := splitSession(packed)
	ctx := context.Background()
	_, err := client.UpdateUser(ctx, signet.UpdateUserInput{
		UserID: userID, SessionToken: token, Name: "Grace",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	events, err := client.QueryAudit(ctx, token, signet.AuditQueryInput{Name: "user_updated", Limit: 10})
	if err != nil || len(events) != 1 || events[0].Outcome != "success" {
		t.Fatalf("events = %+v err = %v", events, err)
	}
	if _, err := client.QueryAudit(ctx, "stale", signet.AuditQueryInput{}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("stale query error = %v", err)
	}
}

func TestSetPasswordForPasswordlessUser(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	mailer := testutil.NewMailer()
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AppURL = "https://app.example.com"
	cfg.Passwordless = &signet.PasswordlessConfig{}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "passkey@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	body := mailer.Messages[len(mailer.Messages)-1].TextBody
	i := strings.Index(body, "token=")
	if i < 0 {
		t.Fatalf("no token: %s", body)
	}
	raw := body[i+len("token="):]
	if j := strings.IndexAny(raw, " \n&"); j >= 0 {
		raw = raw[:j]
	}
	signIn, err := client.VerifyMagicLink(ctx, signet.VerifyMagicLinkInput{Token: raw})
	if err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	if err := client.SetPassword(ctx, signet.SetPasswordInput{
		UserID: signIn.User.ID, SessionToken: signIn.SessionToken, NewPassword: "first password",
	}); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	ok, err := client.VerifyPassword(ctx, signet.VerifyPasswordInput{
		UserID: signIn.User.ID, Password: "first password",
	})
	if err != nil || !ok {
		t.Fatalf("verify first password = %v err = %v", ok, err)
	}
}

func TestQueryAuditUsesConfiguredQueryStore(t *testing.T) {
	sink := &fakeAuditQueryStore{}
	store := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AuditQueryStore = sink
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "query@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn, err := client.SignIn(ctx, signet.SignInInput{Email: "query@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	events, err := client.QueryAudit(ctx, signIn.SessionToken, signet.AuditQueryInput{Limit: 10})
	if err != nil || len(events) == 0 {
		t.Fatalf("events = %+v err = %v", events, err)
	}
	_ = signUp
}

func TestVerifyPasswordRateLimited(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: false}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.VerifyPassword(context.Background(), signet.VerifyPasswordInput{
		UserID: "user-1", Password: "x",
	}); !errors.Is(err, signet.ErrRateLimited) {
		t.Fatalf("rate-limit error = %v", err)
	}
}

func TestWindowLimiterReceivesRuleValues(t *testing.T) {
	window := &fakeWindowLimiter{allow: true}
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.WindowLimiter = window
	cfg.RateLimitRules = map[string]signet.RateLimitRule{
		"signup": {Limit: 7, Window: 2 * time.Minute},
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{Email: "rule@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if window.calls == 0 {
		t.Fatal("window limiter not called")
	}
	if window.lastLimit != 7 || window.lastWindow != 2*time.Minute {
		t.Fatalf("rule values = %d / %s", window.lastLimit, window.lastWindow)
	}
}
