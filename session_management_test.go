package signet_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
)

func TestListSessionsProgrammatic(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	first, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	unknown, err := client.ListSessions(context.Background(), signet.ListSessionsInput{UserID: "does-not-exist"})
	if err != nil || unknown == nil || len(unknown.Sessions) != 0 {
		t.Fatalf("ListSessions(unknown) = (%v, %v)", unknown, err)
	}
	known, err := client.ListSessions(context.Background(), signet.ListSessionsInput{UserID: first.User.ID})
	if err != nil || len(known.Sessions) != 1 {
		t.Fatalf("ListSessions = (%v, %v), want one Session", known, err)
	}
}

func TestListSessionsHTTPHidesTokenHash(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "token_hash") || strings.Contains(rec.Body.String(), "TokenHash") {
		t.Errorf("body leaked a token digest: %s", rec.Body.String())
	}
	var response struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || len(response.Sessions) != 1 {
		t.Errorf("response = %s, want one Session", rec.Body.String())
	}
}

func TestRevokeAllSessionsHTTP(t *testing.T) {
	client, store, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie1 := signInCookie(t, client)
	cookie2 := signInCookie(t, client)
	if len(store.sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(store.sessions))
	}
	req := httptest.NewRequest(http.MethodDelete, "/sessions", nil)
	req.AddCookie(cookie1)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
	if len(store.sessions) != 0 {
		t.Errorf("sessions = %d, want 0", len(store.sessions))
	}
	protected := client.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, cookie := range []*http.Cookie{cookie1, cookie2} {
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 for a revoked cookie", rec.Code)
		}
	}
}

func TestRevokeCurrentSessionHTTP(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	cookie := signInCookie(t, client)
	req := httptest.NewRequest(http.MethodDelete, "/session", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
	if len(rec.Result().Cookies()) != 1 {
		t.Error("expected the session cookie to be cleared")
	}
	protected := client.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 after revoking the current Session", rec.Code)
	}
}

func TestRevokeUnknownSessionIsNoOp(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := client.RevokeSession(context.Background(), signet.RevokeSessionInput{SessionID: "unknown"}); err != nil {
		t.Fatalf("RevokeSession(unknown) = %v, want nil", err)
	}
}
