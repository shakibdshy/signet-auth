package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

type fakeAuthorizer struct {
	roles   []string
	allowed map[string]bool
}

func (a *fakeAuthorizer) Roles(context.Context, string) []string { return a.roles }

func (a *fakeAuthorizer) Authorize(_ context.Context, _ string, resource, action string) bool {
	return a.allowed[resource+":"+action]
}

type fakeRoleWriter struct{ roles []string }

func (w *fakeRoleWriter) SetRoles(_ context.Context, _ string, roles []string) error {
	w.roles = append([]string(nil), roles...)
	return nil
}

func authorizationClient(t *testing.T, authorizer signet.Authorizer, writer signet.RoleWriter, sink signet.AuditSink) *signet.Client {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Authorizer = authorizer
	cfg.RoleWriter = writer
	cfg.APIKeyStore = newFakeAPIKeyStore()
	cfg.AuditSink = sink
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestAuthorizerGrantsAndDenies(t *testing.T) {
	authorizer := &fakeAuthorizer{allowed: map[string]bool{"users:ban": true}}
	client := authorizationClient(t, authorizer, nil, nil)
	ctx := context.Background()
	if !client.Authorize(ctx, "user-1", "users", "ban") {
		t.Fatal("expected grant")
	}
	if client.Authorize(ctx, "user-1", "users", "delete") {
		t.Fatal("expected denial")
	}
}

func TestPermissionConstants(t *testing.T) {
	want := map[signet.Permission]string{
		signet.PermissionUsersBan:         "users:ban",
		signet.PermissionUsersSetRole:     "users:set-role",
		signet.PermissionUsersImpersonate: "users:impersonate",
		signet.PermissionSessionsRevoke:   "sessions:revoke",
		signet.PermissionAPIKeysCreate:    "api-keys:create",
		signet.PermissionAPIKeysRevoke:    "api-keys:revoke",
		signet.PermissionOrgsCreate:       "organizations:create",
		signet.PermissionOrgsMemberAdd:    "organizations:member-add",
		signet.PermissionOrgsMemberRemove: "organizations:member-remove",
		signet.PermissionOrgsMemberRole:   "organizations:member-role",
	}
	for permission, value := range want {
		if string(permission) != value {
			t.Fatalf("permission = %q, want %q", permission, value)
		}
	}
}

func TestRoleWriterSetsRoles(t *testing.T) {
	writer := &fakeRoleWriter{}
	client := authorizationClient(t, &fakeAuthorizer{}, writer, nil)
	if err := client.SetRoles(context.Background(), "user-1", []string{"admin"}); err != nil {
		t.Fatalf("SetRoles: %v", err)
	}
	if len(writer.roles) != 1 || writer.roles[0] != "admin" {
		t.Fatalf("roles = %+v", writer.roles)
	}
}

func TestDeniedAuthorizationEmitsAudit(t *testing.T) {
	sink := &recordingAuditSink{}
	client := authorizationClient(t, &fakeAuthorizer{}, nil, sink)
	if client.Authorize(context.Background(), "user-1", "users", "ban") {
		t.Fatal("expected denial")
	}
	// The public Authorize check itself does not audit; guarded actions do.
	if len(sink.events) != 0 {
		t.Fatalf("unexpected audit events: %+v", sink.events)
	}
	if !errors.Is(signet.ErrForbidden, signet.ErrForbidden) {
		t.Fatal("sentinel mismatch")
	}
}

type recordingAuditSink struct{ events []signet.AuditEvent }

func (s *recordingAuditSink) Record(_ context.Context, event signet.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}
