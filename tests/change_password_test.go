package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

func changePasswordClient(t *testing.T) (*signet.Client, *testutil.Store, *testutil.Mailer) {
	t.Helper()
	store := testutil.NewStore()
	mailer := &testutil.Mailer{}
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, store, mailer
}

func changePasswordSetup(t *testing.T) (*signet.Client, *testutil.Store, *testutil.Mailer, string) {
	t.Helper()
	client, store, mailer := changePasswordClient(t)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse", Name: "Ada",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn, err := client.SignIn(ctx, signet.SignInInput{
		Email: "user@example.com", Password: "correct horse",
	})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	// Outstanding proofs of every kind should be gone after a password change.
	for _, kind := range []signet.TokenKind{
		signet.TokenVerifyEmail, signet.TokenResetPassword, signet.TokenRefresh,
		signet.TokenOAuthLink, signet.TokenOAuthState,
	} {
		if err := store.CreateToken(ctx, &signet.Token{
			ID: string(kind) + "-id", UserID: signIn.User.ID, Kind: kind,
			Hash: string(kind) + "-hash",
		}); err != nil {
			t.Fatalf("CreateToken(%s): %v", kind, err)
		}
	}
	return client, store, mailer, signIn.User.ID
}

func TestChangePasswordSucceedsAndRevokesEverything(t *testing.T) {
	client, store, mailer, userID := changePasswordSetup(t)
	ctx := context.Background()
	err := client.ChangePassword(ctx, signet.ChangePasswordInput{
		UserID: userID, CurrentPassword: "correct horse", NewPassword: "a much better password",
	})
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if len(store.Sessions) != 0 {
		t.Errorf("sessions = %d, want 0", len(store.Sessions))
	}
	if len(store.Tokens) != 0 {
		t.Errorf("tokens = %d, want 0", len(store.Tokens))
	}
	account := store.Accounts[0]
	if account.PasswordHash == "" || account.PasswordHash == "correct horse" {
		t.Error("password verifier was not replaced")
	}
	ok, err := (signet.Argon2idHasher{}).Verify(ctx, account.PasswordHash, "a much better password")
	if err != nil || !ok {
		t.Errorf("new verifier check = %v, %v; want true, nil", ok, err)
	}
	if len(mailer.Messages) != 1 || mailer.Messages[0].Subject != "Your password was changed" {
		t.Errorf("notifications = %+v, want one password-changed message", mailer.Messages)
	}
}

func TestChangePasswordWrongCurrentPasswordHasNoSideEffects(t *testing.T) {
	client, store, _, userID := changePasswordSetup(t)
	ctx := context.Background()
	verifier := store.Accounts[0].PasswordHash
	sessions := len(store.Sessions)
	tokens := len(store.Tokens)

	err := client.ChangePassword(ctx, signet.ChangePasswordInput{
		UserID: userID, CurrentPassword: "wrong", NewPassword: "a much better password",
	})
	if !errors.Is(err, signet.ErrInvalidCredentials) {
		t.Fatalf("error = %v, want ErrInvalidCredentials", err)
	}
	if len(store.Sessions) != sessions || len(store.Tokens) != tokens || store.Accounts[0].PasswordHash != verifier {
		t.Error("failed change mutated Sessions, Tokens or the verifier")
	}
}

func TestChangePasswordOutOfBoundsHasNoSideEffects(t *testing.T) {
	client, store, _, userID := changePasswordSetup(t)
	ctx := context.Background()
	verifier := store.Accounts[0].PasswordHash

	err := client.ChangePassword(ctx, signet.ChangePasswordInput{
		UserID: userID, CurrentPassword: "correct horse", NewPassword: "x",
	})
	if !errors.Is(err, signet.ErrPasswordTooShort) {
		t.Fatalf("error = %v, want ErrPasswordTooShort", err)
	}
	if len(store.Sessions) != 1 || len(store.Tokens) != 5 || store.Accounts[0].PasswordHash != verifier {
		t.Error("invalid new password mutated Sessions, Tokens or the verifier")
	}
}

func TestChangePasswordRateLimited(t *testing.T) {
	client, store, _ := changePasswordClient(t)
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse", Name: "Ada",
	})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	userID := signUp.User.ID
	// Rebuild the client with a denying limiter over the same Store.
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = &testutil.Mailer{}
	cfg.RateLimiter = &testutil.Limiter{Allowed: false}
	client, err = signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	verifier := store.Accounts[0].PasswordHash

	err = client.ChangePassword(ctx, signet.ChangePasswordInput{
		UserID: userID, CurrentPassword: "correct horse", NewPassword: "a much better password",
	})
	if !errors.Is(err, signet.ErrRateLimited) {
		t.Fatalf("error = %v, want ErrRateLimited", err)
	}
	if store.Accounts[0].PasswordHash != verifier {
		t.Error("rate-limited change mutated the verifier")
	}
}

func changePasswordHTTPClient(t *testing.T) (*signet.Client, *testutil.Store) {
	t.Helper()
	client, store, _ := changePasswordClient(t)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse", Name: "Ada",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	return client, store
}

func changePasswordSignIn(t *testing.T, client *signet.Client) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(`{"email":"user@example.com","password":"correct horse"}`))
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP sign-in = %d, body %s", rec.Code, rec.Body.String())
	}
	return rec
}

func TestChangePasswordHTTPEndpoint(t *testing.T) {
	client, store := changePasswordHTTPClient(t)
	ctx := context.Background()
	signInRec := changePasswordSignIn(t, client)
	var csrf struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(signInRec.Body.Bytes(), &csrf); err != nil {
		t.Fatalf("decode sign-in response: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/change-password", strings.NewReader(`{"current_password":"correct horse","new_password":"a much better password"}`))
	for _, c := range signInRec.Result().Cookies() {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", csrf.CSRFToken)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	ok, _ := (signet.Argon2idHasher{}).Verify(ctx, store.Accounts[0].PasswordHash, "a much better password")
	if !ok {
		t.Error("new password verifier was not stored")
	}
}

func TestChangePasswordHTTPWrongPassword(t *testing.T) {
	client, store := changePasswordHTTPClient(t)
	verifier := store.Accounts[0].PasswordHash
	signInRec := changePasswordSignIn(t, client)
	var csrf struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(signInRec.Body.Bytes(), &csrf); err != nil {
		t.Fatalf("decode sign-in response: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/change-password", strings.NewReader(`{"current_password":"wrong","new_password":"a much better password"}`))
	for _, c := range signInRec.Result().Cookies() {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", csrf.CSRFToken)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_credentials") {
		t.Fatalf("status/body = %d %s, want 401 invalid_credentials", rec.Code, rec.Body.String())
	}
	if store.Accounts[0].PasswordHash != verifier {
		t.Error("verifier changed on failed change")
	}
}

func TestChangePasswordHTTPRequiresAuth(t *testing.T) {
	client, _ := changePasswordHTTPClient(t)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/change-password", strings.NewReader(`{}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestChangePasswordHTTPRequiresCSRF(t *testing.T) {
	client, _ := changePasswordHTTPClient(t)
	signInRec := changePasswordSignIn(t, client)
	req := httptest.NewRequest(http.MethodPost, "/change-password", strings.NewReader(`{"current_password":"correct horse","new_password":"a much better password"}`))
	for _, c := range signInRec.Result().Cookies() {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"csrf"`) {
		t.Fatalf("status/body = %d %s, want 403 csrf", rec.Code, rec.Body.String())
	}
}

func TestChangePasswordOAuthOnlyUserReturnsGenericCredentialError(t *testing.T) {
	client, store, _ := changePasswordClient(t)
	ctx := context.Background()
	// Create a User and a provider Account but no credential Account.
	user := &signet.User{ID: "oauth-user", Email: "oauth@example.com", EmailVerified: true}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.CreateAccount(ctx, &signet.Account{
		ID: "oauth-account", UserID: user.ID, Provider: "google", ProviderUserID: "provider-1",
	}); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	verifierBefore := len(store.Accounts)
	err := client.ChangePassword(ctx, signet.ChangePasswordInput{
		UserID: user.ID, CurrentPassword: "correct horse", NewPassword: "a much better password",
	})
	if !errors.Is(err, signet.ErrInvalidCredentials) {
		t.Fatalf("error = %v, want ErrInvalidCredentials", err)
	}
	if len(store.Accounts) != verifierBefore {
		t.Error("OAuth-only change mutated Accounts")
	}
}

func TestChangePasswordThenSignInWithNewPasswordHTTP(t *testing.T) {
	client, store, _ := changePasswordClient(t)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse", Name: "Ada",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn := changePasswordSignIn(t, client)
	var first struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(signIn.Body.Bytes(), &first); err != nil || first.CSRFToken == "" {
		t.Fatalf("decode first sign-in: %v, body = %s", err, signIn.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/change-password",
		strings.NewReader(`{"current_password":"correct horse","new_password":"a much better password"}`))
	for _, c := range signIn.Result().Cookies() {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", first.CSRFToken)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password status = %d body = %s", rec.Code, rec.Body.String())
	}

	again := httptest.NewRecorder()
	client.Handler().ServeHTTP(again, httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader(`{"email":"user@example.com","password":"a much better password"}`)))
	if again.Code != http.StatusOK {
		t.Fatalf("sign-in with new password status = %d body = %s", again.Code, again.Body.String())
	}
	var second struct {
		SessionToken string `json:"session_token"`
		CSRFToken    string `json:"csrf_token"`
	}
	if err := json.Unmarshal(again.Body.Bytes(), &second); err != nil || second.SessionToken == "" || second.CSRFToken == "" {
		t.Fatalf("new sign-in body = %s, err = %v", again.Body.String(), err)
	}
	ok, err := (signet.Argon2idHasher{}).Verify(ctx, store.Accounts[0].PasswordHash, "a much better password")
	if err != nil || !ok {
		t.Fatalf("new verifier = %v, %v", ok, err)
	}

	// The new session and its rotated CSRF token must work together on a
	// protected state-changing route.
	signout := httptest.NewRequest(http.MethodPost, "/signout", strings.NewReader(`{}`))
	for _, c := range again.Result().Cookies() {
		signout.AddCookie(c)
	}
	signout.Header.Set("X-CSRF-Token", second.CSRFToken)
	signedOut := httptest.NewRecorder()
	client.Handler().ServeHTTP(signedOut, signout)
	if signedOut.Code != http.StatusNoContent {
		t.Fatalf("signout with new session status = %d, want 204; body = %s", signedOut.Code, signedOut.Body.String())
	}

	stale := httptest.NewRecorder()
	client.Handler().ServeHTTP(stale, httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader(`{"email":"user@example.com","password":"correct horse"}`)))
	if stale.Code != http.StatusUnauthorized {
		t.Fatalf("old password status = %d, want 401", stale.Code)
	}
}

func TestChangePasswordHTTPRejectsNonPost(t *testing.T) {
	client, store := changePasswordHTTPClient(t)
	signInRec := changePasswordSignIn(t, client)
	var csrf struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(signInRec.Body.Bytes(), &csrf); err != nil {
		t.Fatalf("decode sign-in: %v", err)
	}
	verifier := store.Accounts[0].PasswordHash
	req := httptest.NewRequest(http.MethodGet, "/change-password", strings.NewReader(`{"current_password":"correct horse","new_password":"a much better password"}`))
	for _, c := range signInRec.Result().Cookies() {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", csrf.CSRFToken)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 (body %s)", rec.Code, rec.Body.String())
	}
	if store.Accounts[0].PasswordHash != verifier {
		t.Error("GET changed the verifier")
	}
}
