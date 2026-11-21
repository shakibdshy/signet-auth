package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

func changePasswordClient(t *testing.T, allow bool) (*signet.Client, *testutil.Store, *testutil.Mailer) {
	t.Helper()
	store := testutil.NewStore()
	mailer := &testutil.Mailer{}
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: allow}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, store, mailer
}

func changePasswordSetup(t *testing.T) (*signet.Client, *testutil.Store, *testutil.Mailer, string) {
	t.Helper()
	client, store, mailer := changePasswordClient(t, true)
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
	client, store, _ := changePasswordClient(t, true)
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
