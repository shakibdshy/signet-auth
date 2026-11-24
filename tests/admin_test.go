package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

type adminAuditSink struct{ events []signet.AuditEvent }

func (s *adminAuditSink) Record(_ context.Context, event signet.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func adminClient(t *testing.T, authorizer signet.Authorizer, _ int, sink signet.AuditSink) (*signet.Client, *testutil.Store) {
	t.Helper()
	store := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Authorizer = authorizer
	cfg.AuditSink = sink
	cfg.AdminUserStore = store
	cfg.Accounts = &signet.AccountConfig{FreshWindow: timeDurationHours(1)}
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
	targets, err := client.AdminListUsers(ctx, signet.AdminListUsersInput{ActorID: adminID, SessionToken: sessionToken})
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
	users, _ := client.AdminListUsers(ctx, signet.AdminListUsersInput{ActorID: adminID, SessionToken: sessionToken})
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
	if _, err := client.StopImpersonating(ctx, signet.StopImpersonatingInput{Token: started.Token}); err != nil {
		t.Fatalf("StopImpersonating: %v", err)
	}
	if _, err := client.VerifyAPIKey(ctx, started.Token); err == nil {
		t.Fatal("stopped impersonation token should be invalid")
	}
}

func TestAdminListRevokeSessions(t *testing.T) {
	authorizer := &fakeAuthorizer{allowed: map[string]bool{"sessions:revoke": true}}
	client, _ := adminClient(t, authorizer, 1, nil)
	ctx := context.Background()
	admin, err := client.SignUp(ctx, signet.SignUpInput{Email: "admin@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp admin: %v", err)
	}
	adminSignIn, err := client.SignIn(ctx, signet.SignInInput{Email: "admin@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn admin: %v", err)
	}
	adminID, token := admin.User.ID, adminSignIn.SessionToken
	_, err = client.SignUp(ctx, signet.SignUpInput{Email: "target@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	target, err := client.SignIn(ctx, signet.SignInInput{Email: "target@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	sessions, err := client.AdminListUserSessions(ctx, adminID, target.User.ID, token)
	if err != nil || len(sessions.Sessions) == 0 {
		t.Fatalf("sessions = %+v err = %v", sessions, err)
	}
	if err := client.AdminRevokeUserSession(ctx, adminID, sessions.Sessions[0].ID, token); err != nil {
		t.Fatalf("AdminRevokeUserSession: %v", err)
	}
	if err := client.VerifyFreshSession(ctx, target.SessionToken); err == nil {
		t.Fatal("revoked session still resolves")
	}
}

func TestAdminDeniedAudit(t *testing.T) {
	sink := &adminAuditSink{}
	client, _ := adminClient(t, &fakeAuthorizer{}, 1, sink)
	err := client.BanUser(context.Background(), signet.BanUserInput{
		ActorID: "admin-1", SessionToken: "token", UserID: "target-1",
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("BanUser error = %v", err)
	}
	for _, event := range sink.events {
		if event.Outcome == "denied" && event.Metadata["permission"] == "users:ban" {
			return
		}
	}
	t.Fatalf("no denied audit event: %+v", sink.events)
}

func TestAdminStaleSessionBlocked(t *testing.T) {
	client, _ := adminClient(t, &fakeAuthorizer{allowed: map[string]bool{"users:ban": true}}, 1, nil)
	err := client.BanUser(context.Background(), signet.BanUserInput{
		ActorID: "admin-1", SessionToken: "stale-token", UserID: "target-1",
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("stale BanUser error = %v", err)
	}
}

func TestSelfImpersonationBlocked(t *testing.T) {
	client, _, adminID, token := adminFixture(t, nil)
	_, err := client.ImpersonateUser(context.Background(), signet.ImpersonateUserInput{
		ActorID: adminID, SessionToken: token, UserID: adminID,
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("self impersonation error = %v", err)
	}
}

func TestImpersonationUsesStoreSessionAndSignedCookie(t *testing.T) {
	sink := &adminAuditSink{}
	client, store, adminID, token := adminFixture(t, sink)
	ctx := context.Background()
	users, _ := client.AdminListUsers(ctx, signet.AdminListUsersInput{ActorID: adminID, SessionToken: token})
	var targetID string
	for _, user := range users.Users {
		if user.Email == "target@example.com" {
			targetID = user.ID
		}
	}
	sessionsBefore := len(store.Sessions)
	started, err := client.ImpersonateUser(ctx, signet.ImpersonateUserInput{
		ActorID: adminID, SessionToken: token, UserID: targetID,
	})
	if err != nil {
		t.Fatalf("ImpersonateUser: %v", err)
	}
	if len(store.Sessions) != sessionsBefore+1 {
		t.Fatalf("sessions = %d, want %d", len(store.Sessions), sessionsBefore+1)
	}
	// The temporary Session belongs to the target.
	if err := client.VerifyFreshSession(ctx, started.Token); err != nil {
		t.Fatalf("temporary Session does not resolve: %v", err)
	}
	// The signed cookie carries the admin ID and original token.
	rec := httptest.NewRecorder()
	client.SetImpersonationCookie(rec, adminID, token)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("impersonation cookies = %d", len(cookies))
	}
	req := httptest.NewRequest(http.MethodGet, "/admin-users", nil)
	req.AddCookie(cookies[0])
	gotAdmin, original := client.ImpersonationFromRequest(req)
	if gotAdmin != adminID || original != token {
		t.Fatalf("cookie admin = %q original = %q", gotAdmin, original)
	}
	if !client.IsImpersonating(req) || client.AdminActorFromRequest(req, "target") != adminID {
		t.Fatal("impersonation cookie does not drive admin identity")
	}
	// Tampering is ignored.
	req.AddCookie(&http.Cookie{Name: cookies[0].Name, Value: "tampered.value", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	if client.IsImpersonating(req) {
		// The first valid cookie still wins; test a request with only the tampered one.
		bad := httptest.NewRequest(http.MethodGet, "/admin-users", nil)
		bad.AddCookie(&http.Cookie{Name: cookies[0].Name, Value: "tampered.value", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		if client.IsImpersonating(bad) {
			t.Fatal("tampered impersonation cookie accepted")
		}
	}
	originalToken, err := client.StopImpersonating(ctx, signet.StopImpersonatingInput{
		Token: started.Token, AdminID: adminID, OriginalToken: token,
	})
	if err != nil {
		t.Fatalf("StopImpersonating: %v", err)
	}
	if originalToken != token {
		t.Fatalf("restored token = %q", originalToken)
	}
	if err := client.VerifyFreshSession(ctx, started.Token); err == nil {
		t.Fatal("temporary Session not revoked on stop")
	}
}

func TestSelfDeleteBlockedWhileImpersonating(t *testing.T) {
	client, _, adminID, token := adminFixture(t, nil)
	ctx := context.Background()
	users, _ := client.AdminListUsers(ctx, signet.AdminListUsersInput{ActorID: adminID, SessionToken: token})
	var targetID string
	for _, user := range users.Users {
		if user.Email == "target@example.com" {
			targetID = user.ID
		}
	}
	if _, err := client.ImpersonateUser(ctx, signet.ImpersonateUserInput{
		ActorID: adminID, SessionToken: token, UserID: targetID,
	}); err != nil {
		t.Fatalf("ImpersonateUser: %v", err)
	}
	rec := httptest.NewRecorder()
	client.SetImpersonationCookie(rec, adminID, token)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/confirm-account-deletion", strings.NewReader(`{"token":"anything"}`))
	req.AddCookie(rec.Result().Cookies()[0])
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", csrfToken)
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("deletion status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestAdminHTTPEndpoints(t *testing.T) {
	authorizer := &fakeAuthorizer{allowed: map[string]bool{
		"users:ban": true, "users:set-role": true,
		"sessions:revoke": true, "users:impersonate": true,
	}}
	_, store := adminClient(t, authorizer, 1, nil)
	// AdminSetUserRole requires a RoleWriter.
	writerCfg := testutil.NewConfig()
	writerCfg.Store = store
	writerCfg.Mailer = testutil.NewMailer()
	writerCfg.RateLimiter = &testutil.Limiter{Allowed: true}
	writerCfg.Authorizer = authorizer
	writerCfg.AdminUserStore = store
	writerCfg.RoleWriter = &fakeRoleWriter{}
	writerCfg.Accounts = &signet.AccountConfig{FreshWindow: time.Hour}
	client, err := signet.New(writerCfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "admin@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	target, err := client.SignUp(ctx, signet.SignUpInput{Email: "target@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(ctx, signet.SignInInput{Email: "admin@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	cookies := &http.Cookie{Name: "__Host-signet_session", Value: result.SessionToken, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	post := func(path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.AddCookie(cookies)
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfToken)
		client.Handler().ServeHTTP(rr, req)
		return rr
	}
	get := func(path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookies)
		client.Handler().ServeHTTP(rr, req)
		return rr
	}
	if rr := get("/admin-users"); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), target.User.ID) {
		t.Fatalf("users status = %d body = %s", rr.Code, rr.Body.String())
	}
	if rr := post("/admin-users/role", `{"user_id":"`+target.User.ID+`","roles":["admin"]}`); rr.Code != http.StatusOK {
		t.Fatalf("role status = %d body = %s", rr.Code, rr.Body.String())
	}
	if rr := post("/admin-users/ban", `{"user_id":"`+target.User.ID+`"}`); rr.Code != http.StatusOK {
		t.Fatalf("ban status = %d body = %s", rr.Code, rr.Body.String())
	}
	if !store.Users[target.User.ID].Disabled {
		t.Fatal("target not banned")
	}
	if rr := post("/admin-users/unban", `{"user_id":"`+target.User.ID+`"}`); rr.Code != http.StatusOK {
		t.Fatalf("unban status = %d body = %s", rr.Code, rr.Body.String())
	}
	if rr := get("/admin-user-sessions?user_id=" + target.User.ID); rr.Code != http.StatusOK {
		t.Fatalf("sessions status = %d body = %s", rr.Code, rr.Body.String())
	}
	imp := post("/impersonate", `{"user_id":"`+target.User.ID+`"}`)
	if imp.Code != http.StatusOK {
		t.Fatalf("impersonate status = %d body = %s", imp.Code, imp.Body.String())
	}
	var started struct {
		Token string `json:"Token"`
	}
	if err := json.Unmarshal(imp.Body.Bytes(), &started); err != nil || started.Token == "" {
		t.Fatalf("impersonate decode = %v body = %s", err, imp.Body.String())
	}
	cookieNames := make(map[string]string)
	for _, cookie := range imp.Result().Cookies() {
		cookieNames[cookie.Name] = cookie.Value
	}
	if cookieNames["signet_impersonation"] == "" || cookieNames["__Host-signet_session"] != started.Token {
		t.Fatalf("impersonate cookies = %+v", cookieNames)
	}
}
