package signet_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

func resetClient(t *testing.T) (*signet.Client, *testutil.Store, *testutil.Mailer) {
	t.Helper()
	store := testutil.NewStore()
	mailer := &testutil.Mailer{}
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AppURL = "https://app.example.com"
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, store, mailer
}

func requestReset(t *testing.T, client *signet.Client, mailer *testutil.Mailer, email string) string {
	t.Helper()
	if err := client.SendPasswordReset(context.Background(), signet.SendPasswordResetInput{Email: email}); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}
	if len(mailer.Messages) == 0 {
		t.Fatal("no reset message sent")
	}
	return tokenFromMessage(t, mailer.Messages[len(mailer.Messages)-1])
}

func TestSendPasswordResetHidesUnknownEmail(t *testing.T) {
	client, _, mailer := resetClient(t)
	if err := client.SendPasswordReset(context.Background(), signet.SendPasswordResetInput{Email: "nobody@example.com"}); err != nil {
		t.Fatalf("SendPasswordReset(unknown) = %v, want nil", err)
	}
	if len(mailer.Messages) != 0 {
		t.Errorf("messages = %d, want none", len(mailer.Messages))
	}
}

func TestResetPasswordChangesVerifierAndNotifies(t *testing.T) {
	client, store, mailer := resetClient(t)
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	token := requestReset(t, client, mailer, "user@example.com")
	if err := client.ResetPassword(context.Background(), signet.ResetPasswordInput{
		Token: token, NewPassword: "a-new-password",
	}); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if _, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"}); !errors.Is(err, signet.ErrInvalidCredentials) {
		t.Errorf("old password error = %v, want ErrInvalidCredentials", err)
	}
	if _, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "a-new-password"}); err != nil {
		t.Fatalf("SignIn with new password: %v", err)
	}
	if len(mailer.Messages) < 2 || !strings.Contains(mailer.Messages[len(mailer.Messages)-1].Subject, "changed") {
		t.Errorf("messages = %+v, want a password-changed notification", mailer.Messages)
	}
	if len(store.Tokens) != 0 {
		t.Errorf("tokens = %d, want all reset tokens deleted", len(store.Tokens))
	}
}

func TestResetPasswordRevokesSessionsAndRejectsReplay(t *testing.T) {
	client, store, mailer := resetClient(t)
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"}); err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if len(store.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(store.Sessions))
	}
	token := requestReset(t, client, mailer, "user@example.com")
	if err := client.ResetPassword(context.Background(), signet.ResetPasswordInput{Token: token, NewPassword: "a-new-password"}); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if len(store.Sessions) != 0 {
		t.Errorf("sessions = %d, want all revoked", len(store.Sessions))
	}
	if err := client.ResetPassword(context.Background(), signet.ResetPasswordInput{Token: token, NewPassword: "another-password"}); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("replayed reset error = %v, want ErrTokenInvalid", err)
	}
}

func TestResetPasswordEnforcesPasswordBounds(t *testing.T) {
	client, _, mailer := resetClient(t)
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	token := requestReset(t, client, mailer, "user@example.com")
	if err := client.ResetPassword(context.Background(), signet.ResetPasswordInput{Token: token, NewPassword: "short"}); !errors.Is(err, signet.ErrPasswordTooShort) {
		t.Fatalf("short password error = %v, want ErrPasswordTooShort", err)
	}
}

func TestResetEndpoints(t *testing.T) {
	client, _, mailer := resetClient(t)
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		client.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := post("/send-password-reset", `{"email":"user@example.com"}`); rec.Code != http.StatusOK {
		t.Fatalf("send status = %d, body = %s", rec.Code, rec.Body.String())
	}
	token := tokenFromMessage(t, mailer.Messages[len(mailer.Messages)-1])
	body, _ := json.Marshal(map[string]string{"token": token, "new_password": "a-new-password"})
	if rec := post("/reset-password", string(body)); rec.Code != http.StatusOK {
		t.Fatalf("reset status = %d, body = %s", rec.Code, rec.Body.String())
	}
}
