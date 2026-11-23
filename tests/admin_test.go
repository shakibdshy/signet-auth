package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

type adminAuditSink struct{ events []signet.AuditEvent }

func (s *adminAuditSink) Record(_ context.Context, event signet.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func adminClient(t *testing.T, authorizer signet.Authorizer, freshWindowHours int, sink signet.AuditSink) (*signet.Client, *testutil.Store) {
	t.Helper()
	store := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Authorizer = authorizer
	cfg.AuditSink = sink
	cfg.AdminUserStore = store
	cfg.Accounts = &signet.AccountConfig{FreshWindow: timeDurationHours(freshWindowHours)}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, store
}

func timeDurationHours(hours int) (d time.Duration) {
	return time.Duration(hours) * time.Hour
}

func adminFixture(t *testing.T, sink signet.AuditSink) (*signet.Client, *testutil.Store, string, string) {
	authorizer := &fakeAuthorizer{allowed: map[string]bool{
		"users:ban": true, "users:set-role": true, "users:impersonate": true, "sessions:revoke": true,
	}}
	client, store := adminClient(t, authorizer, 1, sink)
	ctx := context.Background()
	admin, err := client.SignUp(ctx, signet.SignUpInput{Email: "admin@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp admin: %v", err)
	}
	_, err = client.SignUp(ctx, signet.SignUpInput{Email: "target@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp target: %v", err)
	}
	adminSession, err := client.SignIn(ctx, signet.SignInInput{Email: "admin@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn admin: %v", err)
	}
	return client, store, admin.User.ID, adminSession.SessionToken
}

func TestAdminBanRequiresGrant(t *testing.T) {
	client, _ := adminClient(t, &fakeAuthorizer{}, 1, nil)
	adminID := "admin-1"
	err := client.BanUser(context.Background(), signet.BanUserInput{ActorID: adminID, UserID: "target-1"})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("error = %v", err)
	}
}

func TestAdminBanUnbanAndSelfBlock(t *testing.T) {
	sink := &adminAuditSink{}
	client, store, adminID, sessionToken := adminFixture(t, sink)
	ctx := context.Background()
	targets, err := client.AdminListUsers(ctx, signet.AdminListUsersInput{ActorID: adminID})
	if err != nil || len(targets.Users) != 2 {
		t.Fatalf("users = %+v, err = %v", targets, err)
	}
	var targetID string
	for _, user := range targets.Users {
		if user.Email == "target@example.com" {
			targetID = user.ID
		}
	}
	if err := client.BanUser(ctx, signet.BanUserInput{ActorID: adminID, SessionToken: sessionToken, UserID: targetID, Reason: "abuse"}); err != nil {
		t.Fatalf("BanUser: %v", err)
	}
	if !store.Users[targetID].Disabled {
		t.Fatal("target should be banned")
	}
	if err := client.BanUser(ctx, signet.BanUserInput{ActorID: adminID, SessionToken: sessionToken, UserID: adminID}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("self-ban error = %v", err)
	}
	if err := client.UnbanUser(ctx, signet.UnbanUserInput{ActorID: adminID, SessionToken: sessionToken, UserID: targetID}); err != nil {
		t.Fatalf("UnbanUser: %v", err)
	}
	if store.Users[targetID].Disabled {
		t.Fatal("target should be unbanned")
	}
	if len(sink.events) < 3 {
		t.Fatalf("audit events = %+v", sink.events)
	}
}

func TestAdminSetRoleRequiresGrant(t *testing.T) {
	client, _, adminID, _ := adminFixture(t, nil)
	err := client.AdminSetUserRole(context.Background(), signet.AdminSetUserRoleInput{
		ActorID: adminID, UserID: "target-1", Roles: []string{"admin"},
	})
	if err == nil {
		t.Fatal("missing role writer should be rejected")
	}
}

func TestAdminImpersonationLifecycle(t *testing.T) {
	sink := &adminAuditSink{}
	client, _, adminID, sessionToken := adminFixture(t, sink)
	ctx := context.Background()
	targetID := ""
	users, _ := client.AdminListUsers(ctx, signet.AdminListUsersInput{ActorID: adminID})
	for _, user := range users.Users {
		if user.Email == "target@example.com" {
			targetID = user.ID
		}
	}
	started, err := client.ImpersonateUser(ctx, signet.ImpersonateUserInput{ActorID: adminID, SessionToken: sessionToken, UserID: targetID})
	if err != nil {
		t.Fatalf("ImpersonateUser: %v", err)
	}
	if started.Token == "" || started.AdminID != adminID {
		t.Fatalf("impersonation = %+v", started)
	}
	if err := client.StopImpersonating(ctx, signet.StopImpersonatingInput{Token: started.Token}); err != nil {
		t.Fatalf("StopImpersonating: %v", err)
	}
	if _, err := client.VerifyAPIKey(ctx, started.Token); err == nil {
		t.Fatal("stopped impersonation token should be invalid")
	}
}
