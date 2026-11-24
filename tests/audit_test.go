package tests

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

type fakeAuditSink struct {
	mu     sync.Mutex
	events []signet.AuditEvent
	fail   error
}

func (s *fakeAuditSink) Record(_ context.Context, event signet.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return s.fail
}

func (s *fakeAuditSink) names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.events))
	for _, event := range s.events {
		out = append(out, event.Name)
	}
	return out
}

func (s *fakeAuditSink) snapshot() []signet.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]signet.AuditEvent(nil), s.events...)
}

func auditClient(t *testing.T, sink signet.AuditSink) *signet.Client {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	mailer := testutil.NewMailer()
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AuditSink = sink
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = mailer
	return client
}

func hasEvent(names []string, name string) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}

func TestAuditSinkReceivesSecurityEvents(t *testing.T) {
	sink := &fakeAuditSink{}
	client := auditClient(t, sink)
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if err := client.SignOut(ctx, signet.SignOutInput{SessionToken: result.SessionToken}); err != nil {
		t.Fatalf("SignOut: %v", err)
	}
	// ChangePassword revokes all Sessions, so sign out before changing it.
	if err := client.ChangePassword(ctx, signet.ChangePasswordInput{
		UserID: signUp.User.ID, CurrentPassword: "correct horse", NewPassword: "new strong password",
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	names := sink.names()
	for _, want := range []string{"sign_up", "sign_in_success", "password_changed", "sign_out"} {
		if !hasEvent(names, want) {
			t.Fatalf("missing %q in %+v", want, names)
		}
	}
}

func TestAuditEventsContainNoSecrets(t *testing.T) {
	sink := &fakeAuditSink{}
	client := auditClient(t, sink)
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	for _, event := range sink.snapshot() {
		for _, value := range event.Metadata {
			if strings.Contains(value, "correct horse") || strings.Contains(value, result.SessionToken) {
				t.Fatalf("secret in audit metadata: %+v", event)
			}
		}
	}
	if signUp.User.ID == "" {
		t.Fatal("missing user")
	}
}

func TestAuditSinkFailureDoesNotBreakAuthentication(t *testing.T) {
	sink := &fakeAuditSink{fail: errors.New("sink down")}
	client := auditClient(t, sink)
	result, err := client.SignIn(context.Background(), signet.SignInInput{
		Email: "nobody@example.com", Password: "correct horse",
	})
	if err == nil || result != nil {
		t.Fatalf("unknown user should still fail generically: %+v, %v", result, err)
	}
	signUp, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse",
	})
	if err != nil || signUp == nil {
		t.Fatalf("sink failure must not break sign-up: %+v, %v", signUp, err)
	}
}
