package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

func usernameClient(t *testing.T, configure func(*signet.Config)) (*signet.Client, *testutil.Store) {
	t.Helper()
	store := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	if configure != nil {
		configure(&cfg)
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, store
}

func TestUsernameSignUpAndSignIn(t *testing.T) {
	client, store := usernameClient(t, nil)
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse", Username: "Ada.Lovelace",
	})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	accounts, _ := store.AccountsForUser(ctx, signUp.User.ID)
	var found bool
	for _, account := range accounts {
		if account.Provider == "username" && account.ProviderUserID == "ada.lovelace" {
			found = true
		}
	}
	if !found {
		t.Fatalf("username Account missing: %+v", accounts)
	}
	result, err := client.SignIn(ctx, signet.SignInInput{Username: "ADA.LOVELACE", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn by username: %v", err)
	}
	if result.User.ID != signUp.User.ID || result.SessionToken == "" {
		t.Fatalf("result = %+v", result)
	}
}

func TestUsernameSignInIsCaseInsensitiveAndGenericOnFailure(t *testing.T) {
	client, _ := usernameClient(t, nil)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse", Username: "ada",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	for _, name := range []string{"ada", "ADA", "Ada"} {
		if _, err := client.SignIn(ctx, signet.SignInInput{Username: name, Password: "correct horse"}); err != nil {
			t.Fatalf("SignIn %q: %v", name, err)
		}
	}
	if _, err := client.SignIn(ctx, signet.SignInInput{Username: "ada", Password: "wrong password"}); !errors.Is(err, signet.ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v", err)
	}
	if _, err := client.SignIn(ctx, signet.SignInInput{Username: "missing", Password: "wrong password"}); !errors.Is(err, signet.ErrInvalidCredentials) {
		t.Fatalf("unknown username error = %v", err)
	}
}

func TestUsernameDuplicateRejected(t *testing.T) {
	client, _ := usernameClient(t, nil)
	ctx := context.Background()
	for i, email := range []string{"one@example.com", "two@example.com"} {
		in := signet.SignUpInput{Email: email, Password: "correct horse", Username: "taken"}
		_, err := client.SignUp(ctx, in)
		if i == 0 && err != nil {
			t.Fatalf("first SignUp: %v", err)
		}
		if i == 1 && !errors.Is(err, signet.ErrUsernameTaken) {
			t.Fatalf("duplicate error = %v, want ErrUsernameTaken", err)
		}
	}
}

func TestUsernameValidationAndReservedNames(t *testing.T) {
	client, _ := usernameClient(t, func(cfg *signet.Config) {
		cfg.Username = &signet.UsernameConfig{Reserved: []string{"admin"}}
	})
	ctx := context.Background()
	for _, name := range []string{"ab", "has space", "bad-name", "admin"} {
		if _, err := client.SignUp(ctx, signet.SignUpInput{
			Email: name + "@example.com", Password: "correct horse", Username: name,
		}); err == nil {
			t.Errorf("username %q should be rejected", name)
		}
	}
}
