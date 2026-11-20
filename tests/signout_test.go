package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

func TestSignOutRevokesSession(t *testing.T) {
	client, store, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if err := client.SignOut(context.Background(), signet.SignOutInput{SessionToken: result.SessionToken}); err != nil {
		t.Fatalf("SignOut: %v", err)
	}
	if len(store.Sessions) != 0 {
		t.Errorf("sessions = %d, want 0 after sign-out", len(store.Sessions))
	}
}

func TestSignOutUnknownTokenIsSuccessfulNoOp(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := client.SignOut(context.Background(), signet.SignOutInput{SessionToken: "unknown-token"}); err != nil {
		t.Fatalf("SignOut(unknown) error = %v, want nil", err)
	}
}

func TestSignOutHTTPEndpoint(t *testing.T) {
	client, store, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	body, err := json.Marshal(map[string]string{"session_token": result.SessionToken})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/signout", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
	if len(store.Sessions) != 0 {
		t.Errorf("sessions = %d, want 0 after sign-out", len(store.Sessions))
	}
}

func TestSignOutDoesNotLogToken(t *testing.T) {
	var logs bytes.Buffer
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = fakeMailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.PasswordHasher = testutil.FastHasher{}
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.SignOut(context.Background(), signet.SignOutInput{SessionToken: "secret-session-token"}); err != nil {
		t.Fatalf("SignOut: %v", err)
	}
	if strings.Contains(logs.String(), "secret-session-token") {
		t.Errorf("logs leaked the Session token: %q", logs.String())
	}
}

func TestFullHTTPAuthFlow(t *testing.T) {
	client, store, _ := newAuthClient()
	handler := client.Handler()
	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := post("/signup", `{"email":"user@example.com","password":"password123"}`); rec.Code != http.StatusCreated {
		t.Fatalf("sign-up status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec := post("/signin", `{"email":"user@example.com","password":"password123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign-in status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var signedIn struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &signedIn); err != nil {
		t.Fatalf("decode sign-in: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"session_token": signedIn.SessionToken})
	if rec := post("/signout", string(body)); rec.Code != http.StatusNoContent {
		t.Fatalf("sign-out status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if len(store.Sessions) != 0 {
		t.Errorf("sessions = %d, want 0", len(store.Sessions))
	}
}
