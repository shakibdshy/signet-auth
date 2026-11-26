package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shakibdshy/signet-auth"
)

func meResponse(t *testing.T, client *signet.Client, cookie *http.Cookie) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /me status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET /me body = %s", rec.Body.String())
	}
	return body
}

func TestMeReturnsUsernameVerificationAndTimestamps(t *testing.T) {
	client, _, _ := newAuthClient()
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "password123", Username: "ada",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec := signInOverHTTPWithUserAgent(t, client, "")
	body := meResponse(t, client, sessionCookieFromResponse(t, rec))
	if got, ok := body["username"].(string); !ok || got != "ada" {
		t.Fatalf("GET /me username = %#v, want \"ada\"", body["username"])
	}
	if got, ok := body["email_verified"].(bool); !ok || got {
		t.Fatalf("GET /me email_verified = %#v, want false before verification", body["email_verified"])
	}
	created, ok := body["created_at"].(string)
	if !ok || created == "" {
		t.Fatalf("GET /me created_at = %#v, want an RFC 3339 timestamp", body["created_at"])
	}
	updated, ok := body["updated_at"].(string)
	if !ok || updated == "" {
		t.Fatalf("GET /me updated_at = %#v, want an RFC 3339 timestamp", body["updated_at"])
	}
	if parsed, err := time.Parse(time.RFC3339, created); err != nil || !parsed.Equal(testTime) {
		t.Fatalf("GET /me created_at = %s, want %s", created, testTime.Format(time.RFC3339))
	}
}

func TestMeUsernameIsEmptyForEmailOnlyUser(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec := signInOverHTTPWithUserAgent(t, client, "")
	body := meResponse(t, client, sessionCookieFromResponse(t, rec))
	got, ok := body["username"].(string)
	if !ok {
		t.Fatalf("GET /me username missing or not a string: %s", rec.Body.String())
	}
	if got != "" {
		t.Fatalf("GET /me username = %#v, want an empty string", got)
	}
}

func TestMeEmailVerifiedTrueAfterVerification(t *testing.T) {
	client, store, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	user, err := store.UserByEmail(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("UserByEmail: %v", err)
	}
	user.EmailVerified = true
	user.UpdatedAt = testTime.Add(time.Minute)
	if err := store.UpdateUser(context.Background(), user); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	rec := signInOverHTTPWithUserAgent(t, client, "")
	body := meResponse(t, client, sessionCookieFromResponse(t, rec))
	if got, ok := body["email_verified"].(bool); !ok || !got {
		t.Fatalf("GET /me email_verified = %#v, want true after verification", body["email_verified"])
	}
	updated, ok := body["updated_at"].(string)
	if !ok || updated != testTime.Add(time.Minute).Format(time.RFC3339) {
		t.Fatalf("GET /me updated_at = %#v, want the store value", body["updated_at"])
	}
}
