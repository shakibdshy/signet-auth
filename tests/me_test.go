package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

func meClient(t *testing.T) (*signet.Client, string) {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "me@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn, err := client.SignIn(ctx, signet.SignInInput{Email: "me@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	return client, signUp.User.ID + "|" + signIn.SessionToken
}

func TestMeEndpoint(t *testing.T) {
	client, packed := meClient(t)
	_, token := splitSession(packed)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-signet_session", Value: token, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rr := httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "me@example.com") {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	for _, secretField := range []string{"password_hash", "token_hash", "\"hash\""} {
		if strings.Contains(rr.Body.String(), secretField) {
			t.Fatalf("response leaked %s: %s", secretField, rr.Body.String())
		}
	}
}

func TestMeEndpointRequiresSession(t *testing.T) {
	client, _ := meClient(t)
	rr := httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/me", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
}
