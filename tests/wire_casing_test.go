package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

// The two endpoints that serialise result structs whole once emitted Go-cased
// JSON keys (User, SessionToken, Sessions); the wire is snake_case everywhere,
// like every other endpoint.

func TestPasskeyFinishWireKeysAreSnakeCase(t *testing.T) {
	protocol := &fakePasskeyProtocol{}
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Passkeys = &signet.PasskeysConfig{
		RPID: "example.com", RPOrigins: []string{"https://example.com"},
		Store: newFakePasskeyStore(), Protocol: protocol,
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	userID, _ := passkeyUser(t, client)
	protocol.userID = userID
	ctx := context.Background()
	begin, err := client.BeginPasskeySignIn(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/passkeys/signin-finish",
		strings.NewReader(`{"token":"`+begin.Token+`","response":{}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if _, ok := body["user"]; !ok {
		t.Fatalf("passkey finish must return the lowercase user key: %s", rec.Body.String())
	}
	if _, ok := body["session_token"]; !ok {
		t.Fatalf("passkey finish must return the lowercase session_token key: %s", rec.Body.String())
	}
	for _, goCased := range []string{"User", "SessionToken"} {
		if _, ok := body[goCased]; ok {
			t.Fatalf("passkey finish still returns the Go-cased %q key: %s", goCased, rec.Body.String())
		}
	}
}

func TestAdminUserSessionsWireKeysAreSnakeCase(t *testing.T) {
	authorizer := &fakeAuthorizer{allowed: map[string]bool{"sessions:revoke": true}}
	client, _ := adminClient(t, authorizer, 1, nil)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "admin@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp admin: %v", err)
	}
	adminSignIn, err := client.SignIn(ctx, signet.SignInInput{Email: "admin@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn admin: %v", err)
	}
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "target@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	target, err := client.SignIn(ctx, signet.SignInInput{Email: "target@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin-user-sessions?user_id="+target.User.ID, nil)
	req.AddCookie(&http.Cookie{Name: "__Host-signet_session", Value: adminSignIn.SessionToken, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if _, ok := body["sessions"]; !ok {
		t.Fatalf("admin session list must return the lowercase sessions key: %s", rec.Body.String())
	}
	if _, ok := body["Sessions"]; ok {
		t.Fatalf("admin session list still returns the Go-cased Sessions key: %s", rec.Body.String())
	}
}
