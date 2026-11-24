package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
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
	client := authorizationClient(t, &fakeAuthorizer{allowed: map[string]bool{"users:set-role": true}}, writer, nil)
	if err := client.SetRoles(context.Background(), "user-1", []string{"admin"}); err != nil {
		t.Fatalf("SetRoles: %v", err)
	}
	if len(writer.roles) != 1 || writer.roles[0] != "admin" {
		t.Fatalf("roles = %+v", writer.roles)
	}
}

func TestAuthorizeDenialEmitsAudit(t *testing.T) {
	sink := &recordingAuditSink{}
	client := authorizationClient(t, &fakeAuthorizer{}, nil, sink)
	if client.Authorize(context.Background(), "user-1", "users", "ban") {
		t.Fatal("expected denial")
	}
	if len(sink.events) != 1 || sink.events[0].Outcome != "denied" {
		t.Fatalf("audit events = %+v", sink.events)
	}
}

type recordingAuditSink struct{ events []signet.AuditEvent }

func (s *recordingAuditSink) Record(_ context.Context, event signet.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func TestDeniedGuardedActionEmitsAudit(t *testing.T) {
	sink := &recordingAuditSink{}
	client := authorizationClient(t, &fakeAuthorizer{}, nil, sink)
	_, err := client.CreateAPIKey(context.Background(), signet.CreateAPIKeyInput{OwnerUserID: "user-1"})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("CreateAPIKey error = %v", err)
	}
	if len(sink.events) != 1 || sink.events[0].Outcome != "denied" ||
		sink.events[0].Metadata["permission"] != "api-keys:create" {
		t.Fatalf("audit events = %+v", sink.events)
	}
}

func TestMemoryAuthorizerFromStatements(t *testing.T) {
	authorizer := signet.NewMemoryAuthorizer(
		signet.RoleStatements{"admin": {signet.PermissionUsersBan}},
		func(_ context.Context, _ string) []string { return []string{"admin"} },
	)
	if !authorizer.Authorize(context.Background(), "user-1", "users", "ban") {
		t.Fatal("statement grant missing")
	}
	if authorizer.Authorize(context.Background(), "user-1", "users", "delete") {
		t.Fatal("unlisted permission granted")
	}
}

func TestAuthorizeInWiring(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AuthorizeIn = &fakeAuthorizeIn{}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !client.AuthorizeIn(context.Background(), "user-1", "org-1", "organizations", "create") {
		t.Fatal("AuthorizeIn not wired")
	}
}

type fakeAuthorizeIn struct{}

func (*fakeAuthorizeIn) AuthorizeIn(context.Context, string, string, string, string) bool {
	return true
}

func TestSystemAPIKeyUsesSentinelOwner(t *testing.T) {
	store := newFakeAPIKeyStore()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.APIKeyStore = store
	cfg.Authorizer = &sentinelAuthorizer{}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "u@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn, err := client.SignIn(ctx, signet.SignInInput{Email: "u@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	created, err := client.CreateAPIKey(ctx, signet.CreateAPIKeyInput{SessionToken: signIn.SessionToken})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if created.Key.OwnerUserID != signet.SystemOwnerID {
		t.Fatalf("owner = %q, want %q", created.Key.OwnerUserID, signet.SystemOwnerID)
	}
	if !sentinelAuthorizerLastOwnerIsSystem() {
		t.Fatal("system key was not authorized under sentinel owner")
	}
}

var sentinelAuthorizerLastOwner string

type sentinelAuthorizer struct{}

func (*sentinelAuthorizer) Roles(context.Context, string) []string { return nil }

func (*sentinelAuthorizer) Authorize(_ context.Context, userID, _, _ string) bool {
	sentinelAuthorizerLastOwner = userID
	return userID == signet.SystemOwnerID
}

func sentinelAuthorizerLastOwnerIsSystem() bool {
	return sentinelAuthorizerLastOwner == signet.SystemOwnerID
}

func TestForbiddenSentinelIsDistinct(t *testing.T) {
	if signet.ErrForbidden.Error() != "signet: forbidden" {
		t.Fatalf("unexpected sentinel: %v", signet.ErrForbidden)
	}
	if errors.Is(signet.ErrForbidden, signet.ErrNotFound) {
		t.Fatal("ErrForbidden must not match ErrNotFound")
	}
}
