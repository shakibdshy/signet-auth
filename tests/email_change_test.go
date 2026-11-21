package tests

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

func emailChangeClient(t *testing.T) (*signet.Client, *testutil.Store, *testutil.Mailer) {
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

func emailChangeTokenFromMail(t *testing.T, mailer *testutil.Mailer) string {
	t.Helper()
	if len(mailer.Messages) == 0 {
		t.Fatal("no verification email captured")
	}
	body := mailer.Messages[0].TextBody
	i := strings.Index(body, "token=")
	if i < 0 {
		t.Fatalf("no token in email body: %q", body)
	}
	raw := body[i+len("token="):]
	if j := strings.IndexAny(raw, " \n"); j >= 0 {
		raw = raw[:j]
	}
	return raw
}

func emailChangeSetup(t *testing.T) (*signet.Client, *testutil.Store, *testutil.Mailer, string) {
	t.Helper()
	client, store, mailer := emailChangeClient(t)
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "old@example.com", Password: "correct horse", Name: "Ada"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	return client, store, mailer, signUp.User.ID
}

func TestEmailChangeRequestAndVerify(t *testing.T) {
	client, store, mailer, userID := emailChangeSetup(t)
	ctx := context.Background()
	initialVerified := store.Users[userID].EmailVerified
	if err := client.RequestEmailChange(ctx, signet.ChangeEmailInput{
		UserID: userID, NewEmail: "new@example.com", CurrentPassword: "correct horse",
	}); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	if len(store.Tokens) == 0 || store.Tokens[0].Kind != signet.TokenChangeEmail {
		t.Fatalf("change token not issued: %+v", store.Tokens)
	}
	if store.Users[userID].Email != "old@example.com" || store.Users[userID].EmailVerified != initialVerified {
		t.Fatal("old email should remain active and verified until consumption")
	}
	if len(mailer.Messages) != 1 || mailer.Messages[0].Subject != "Verify your email change" {
		t.Fatalf("messages = %+v", mailer.Messages)
	}
}

func TestEmailChangeRequestRejectsInvalidInputs(t *testing.T) {
	client, store, _, userID := emailChangeSetup(t)
	ctx := context.Background()
	_, err := client.SignUp(ctx, signet.SignUpInput{Email: "taken@example.com", Password: "correct horse", Name: "Bob"})
	if err != nil {
		t.Fatalf("SignUp second user: %v", err)
	}
	before := len(store.Tokens)
	for name, in := range map[string]signet.ChangeEmailInput{
		"wrong password":  {UserID: userID, NewEmail: "new@example.com", CurrentPassword: "wrong"},
		"malformed email": {UserID: userID, NewEmail: "not-an-email", CurrentPassword: "correct horse"},
		"taken email":     {UserID: userID, NewEmail: "taken@example.com", CurrentPassword: "correct horse"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := client.RequestEmailChange(ctx, in); err == nil {
				t.Fatal("expected error")
			}
			if len(store.Tokens) != before {
				t.Fatalf("tokens = %d, want %d", len(store.Tokens), before)
			}
		})
	}
}

func TestEmailChangeVerifySingleUseAndUniqueness(t *testing.T) {
	client, store, mailer, userID := emailChangeSetup(t)
	ctx := context.Background()
	if err := client.RequestEmailChange(ctx, signet.ChangeEmailInput{
		UserID: userID, NewEmail: "new@example.com", CurrentPassword: "correct horse",
	}); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	raw := emailChangeTokenFromMail(t, mailer)
	if err := client.VerifyEmailChange(ctx, signet.VerifyEmailChangeInput{Token: raw}); err != nil {
		t.Fatalf("VerifyEmailChange: %v", err)
	}
	user := store.Users[userID]
	if user.Email != "new@example.com" || user.EmailVerified {
		t.Errorf("email = %q verified = %v", user.Email, user.EmailVerified)
	}
	if err := client.VerifyEmailChange(ctx, signet.VerifyEmailChangeInput{Token: raw}); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("replay error = %v, want ErrTokenInvalid", err)
	}
}

func TestEmailChangeUniquenessRaceAtConsume(t *testing.T) {
	client, store, mailer, userID := emailChangeSetup(t)
	ctx := context.Background()
	if err := client.RequestEmailChange(ctx, signet.ChangeEmailInput{
		UserID: userID, NewEmail: "race@example.com", CurrentPassword: "correct horse",
	}); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	other := &signet.User{ID: "other", Email: "race@example.com"}
	if err := store.CreateUser(ctx, other); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	raw := emailChangeTokenFromMail(t, mailer)
	if err := client.VerifyEmailChange(ctx, signet.VerifyEmailChangeInput{Token: raw}); !errors.Is(err, signet.ErrEmailAlreadyExists) {
		t.Fatalf("error = %v, want ErrEmailAlreadyExists", err)
	}
	if store.Users[userID].Email != "old@example.com" {
		t.Error("email changed despite uniqueness failure")
	}
}

func emailChangeSignInHTTP(t *testing.T, client *signet.Client) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(`{"email":"old@example.com","password":"correct horse"}`))
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP sign-in = %d, body %s", rec.Code, rec.Body.String())
	}
	return rec
}

func TestEmailChangeHTTPEndpoints(t *testing.T) {
	client, store, mailer, userID := emailChangeSetup(t)
	signInRec := emailChangeSignInHTTP(t, client)
	var signInBody struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(signInRec.Body.Bytes(), &signInBody); err != nil {
		t.Fatalf("decode sign-in: %v", err)
	}
	post := func(path, body string, withCookies bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if withCookies {
			for _, c := range signInRec.Result().Cookies() {
				req.AddCookie(c)
			}
		}
		req.Header.Set("X-CSRF-Token", signInBody.CSRFToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		client.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := post("/change-email", `{"new_email":"web@example.com","current_password":"correct horse"}`, true); rec.Code != http.StatusOK {
		t.Fatalf("change-email = %d %s", rec.Code, rec.Body.String())
	}
	raw := emailChangeTokenFromMail(t, mailer)
	if rec := post("/verify-change-email", `{"token":"`+raw+`"}`, true); rec.Code != http.StatusOK {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body.String())
	}
	if store.Users[userID].Email != "web@example.com" {
		t.Error("email not changed via HTTP")
	}
}

func TestEmailChangeHTTPRequiresAuthAndCSRF(t *testing.T) {
	client, _, _, _ := emailChangeSetup(t)
	req := httptest.NewRequest(http.MethodPost, "/change-email", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session = %d, want 401", rec.Code)
	}
	signInRec := emailChangeSignInHTTP(t, client)
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(signInRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode sign-in: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/change-email", strings.NewReader(`{}`))
	for _, c := range signInRec.Result().Cookies() {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no CSRF = %d, want 403", rec.Code)
	}
}

func TestEmailChangeTakenAddressUsesGenericError(t *testing.T) {
	client, _, _, userID := emailChangeSetup(t)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "taken@example.com", Password: "correct horse", Name: "Bob"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	err := client.RequestEmailChange(ctx, signet.ChangeEmailInput{
		UserID: userID, NewEmail: "taken@example.com", CurrentPassword: "correct horse",
	})
	if !errors.Is(err, signet.ErrInvalidEmail) {
		t.Fatalf("error = %v, want generic ErrInvalidEmail", err)
	}
}
