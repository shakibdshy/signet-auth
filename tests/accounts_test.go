package tests

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

func accountClient(t *testing.T, clock *testutil.Clock) (*signet.Client, *testutil.Store, string, string) {
	t.Helper()
	store := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Clock = clock
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse", Username: "ada",
	})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	return client, store, signUp.User.ID, result.SessionToken
}

func extraAccount(t *testing.T, store *testutil.Store, userID string) string {
	t.Helper()
	account := &signet.Account{
		ID: "extra-account", UserID: userID, Provider: "google",
		ProviderUserID: "provider-user", Email: "user@example.com",
	}
	if err := store.CreateAccount(context.Background(), account); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	return account.ID
}

func TestListAccountsReturnsSafeFields(t *testing.T) {
	clock := &testutil.Clock{At: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	client, _, userID, _ := accountClient(t, clock)
	result, err := client.ListAccounts(context.Background(), signet.ListAccountsInput{UserID: userID})
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(result.Accounts) != 2 {
		t.Fatalf("accounts = %+v, want 2", result.Accounts)
	}
	for _, account := range result.Accounts {
		encoded, err := json.Marshal(account)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if strings.Contains(string(encoded), "password") || strings.Contains(string(encoded), "verifier") {
			t.Fatalf("sensitive field leaked: %s", encoded)
		}
	}
}

func TestUnlinkAccountRefusesLastAccount(t *testing.T) {
	clock := &testutil.Clock{At: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	client, _, userID, token := accountClient(t, clock)
	all, _ := client.ListAccounts(context.Background(), signet.ListAccountsInput{UserID: userID})
	var credentialID string
	for _, a := range all.Accounts {
		if a.Provider == "credential" {
			credentialID = a.ID
		}
	}
	// Remove the extra account first, leaving the credential account.
	if err := client.UnlinkAccount(context.Background(), signet.UnlinkAccountInput{
		UserID: userID, AccountID: extraAccountID(all.Accounts), SessionToken: token,
	}); err != nil {
		t.Fatalf("first unlink: %v", err)
	}
	err := client.UnlinkAccount(context.Background(), signet.UnlinkAccountInput{
		UserID: userID, AccountID: credentialID, SessionToken: token,
	})
	if !errors.Is(err, signet.ErrLastAccount) {
		t.Fatalf("last-account error = %v", err)
	}
}

func extraAccountID(accounts []*signet.AccountInfo) string {
	for _, a := range accounts {
		if a.Provider == "username" || a.Provider == "google" {
			return a.ID
		}
	}
	return ""
}

func TestUnlinkAccountRequiresFreshSession(t *testing.T) {
	clock := &testutil.Clock{At: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	client, store, userID, token := accountClient(t, clock)
	accountID := extraAccount(t, store, userID)
	clock.At = clock.At.Add(6 * time.Minute)
	err := client.UnlinkAccount(context.Background(), signet.UnlinkAccountInput{
		UserID: userID, AccountID: accountID, SessionToken: token,
	})
	if !errors.Is(err, signet.ErrSessionNotFresh) {
		t.Fatalf("stale session error = %v", err)
	}
}

func TestUnlinkAccountRejectsForeignAccount(t *testing.T) {
	clock := &testutil.Clock{At: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	client, store, userID, token := accountClient(t, clock)
	extraAccount(t, store, userID)
	err := client.UnlinkAccount(context.Background(), signet.UnlinkAccountInput{
		UserID: userID, AccountID: "not-an-account", SessionToken: token,
	})
	if !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("foreign account error = %v", err)
	}
}
