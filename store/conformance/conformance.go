// Package conformance provides a shared test suite for signet.Store
// implementations. Adapter authors and application developers can run it with
// Run to verify the full persistence contract.
package conformance

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shakibdshy/signet-auth"
)

// Run executes the Store conformance suite. The factory must return a fresh,
// migrated Store for each case.
func Run(t *testing.T, factory func(t *testing.T) signet.Store) {
	t.Helper()
	cases := []struct {
		name string
		fn   func(*testing.T, signet.Store)
	}{
		{"users", testUsers},
		{"accounts", testAccounts},
		{"sessions", testSessions},
		{"tokens", testTokens},
		{"token_concurrency", testTokenConcurrency},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, factory(t)) })
	}
}

func testUsers(t *testing.T, store signet.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := store.UserByID(ctx, "missing"); !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("UserByID(missing) error = %v, want ErrNotFound", err)
	}
	if _, err := store.UserByEmail(ctx, "missing@example.com"); !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("UserByEmail(missing) error = %v, want ErrNotFound", err)
	}
	user := &signet.User{ID: "user-1", Email: "user@example.com", Name: "Ada", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := store.UserByID(ctx, user.ID)
	if err != nil || got.Email != user.Email || got.Name != user.Name {
		t.Fatalf("UserByID = (%v, %v)", got, err)
	}
	gotByEmail, err := store.UserByEmail(ctx, user.Email)
	if err != nil || gotByEmail.ID != user.ID {
		t.Fatalf("UserByEmail = (%v, %v)", gotByEmail, err)
	}
	got.Name = "Grace"
	if err := store.UpdateUser(ctx, got); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	updated, err := store.UserByID(ctx, user.ID)
	if err != nil || updated.Name != "Grace" {
		t.Fatalf("after UpdateUser = (%v, %v)", updated, err)
	}
	if err := store.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := store.UserByID(ctx, user.ID); !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("after DeleteUser error = %v, want ErrNotFound", err)
	}
}

func testAccounts(t *testing.T, store signet.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := store.AccountByProvider(ctx, "google", "provider-1"); !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("AccountByProvider(missing) error = %v, want ErrNotFound", err)
	}
	if err := store.CreateUser(ctx, &signet.User{ID: "user-1", Email: "user@example.com", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	account := &signet.Account{
		ID: "account-1", UserID: "user-1", Provider: "google", ProviderUserID: "provider-1",
		Email: "user@example.com", EmailVerified: false, CreatedAt: now,
	}
	if err := store.CreateAccount(ctx, account); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	accounts, err := store.AccountsForUser(ctx, "user-1")
	if err != nil || len(accounts) != 1 {
		t.Fatalf("AccountsForUser = (%v, %v), want one", accounts, err)
	}
	found, err := store.AccountByProvider(ctx, "google", "provider-1")
	if err != nil || found.ID != account.ID {
		t.Fatalf("AccountByProvider = (%v, %v)", found, err)
	}
	found.EmailVerified = true
	if err := store.UpdateAccount(ctx, found); err != nil {
		t.Fatalf("UpdateAccount: %v", err)
	}
	updated, err := store.AccountByProvider(ctx, "google", "provider-1")
	if err != nil || !updated.EmailVerified {
		t.Fatalf("after UpdateAccount = (%v, %v)", updated, err)
	}
	if err := store.DeleteAccount(ctx, account.ID); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if _, err := store.AccountByProvider(ctx, "google", "provider-1"); !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("after DeleteAccount error = %v, want ErrNotFound", err)
	}
}

func testSessions(t *testing.T, store signet.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := store.SessionByHash(ctx, "missing"); !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("SessionByHash(missing) error = %v, want ErrNotFound", err)
	}
	if err := store.CreateUser(ctx, &signet.User{ID: "user-1", Email: "user@example.com", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	session := &signet.Session{
		ID: "session-1", UserID: "user-1", TokenHash: "digest-1",
		CreatedAt: now, LastSeenAt: now,
		IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour),
	}
	if err := store.CreateSession(ctx, session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	found, err := store.SessionByHash(ctx, "digest-1")
	if err != nil || found.UserID != "user-1" {
		t.Fatalf("SessionByHash = (%v, %v)", found, err)
	}
	newIdle := now.Add(2 * time.Minute)
	if err := store.TouchSession(ctx, session.ID, newIdle); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	touched, err := store.SessionByHash(ctx, "digest-1")
	if err != nil || !touched.IdleExpiresAt.Equal(newIdle) {
		t.Fatalf("after TouchSession = (%v, %v)", touched, err)
	}
	sessions, err := store.ListSessionsForUser(ctx, "user-1")
	if err != nil || len(sessions) != 1 {
		t.Fatalf("ListSessionsForUser = (%v, %v)", sessions, err)
	}
	second := &signet.Session{
		ID: "session-2", UserID: "user-1", TokenHash: "digest-2",
		CreatedAt: now, LastSeenAt: now,
		IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour),
	}
	if err := store.CreateSession(ctx, second); err != nil {
		t.Fatalf("CreateSession second: %v", err)
	}
	if err := store.DeleteSession(ctx, second.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := store.SessionByHash(ctx, "digest-2"); !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("after DeleteSession error = %v, want ErrNotFound", err)
	}
	if err := store.DeleteSessionsForUser(ctx, "user-1"); err != nil {
		t.Fatalf("DeleteSessionsForUser: %v", err)
	}
	if _, err := store.SessionByHash(ctx, "digest-1"); !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("after DeleteSessionsForUser error = %v, want ErrNotFound", err)
	}
}

func testTokens(t *testing.T, store signet.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := store.TokenByHash(ctx, signet.TokenResetPassword, "missing"); !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("TokenByHash(missing) error = %v, want ErrNotFound", err)
	}
	if err := store.CreateUser(ctx, &signet.User{ID: "user-1", Email: "user@example.com", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token := &signet.Token{
		ID: "token-1", UserID: "user-1", Kind: signet.TokenResetPassword,
		Hash: "digest-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := store.CreateToken(ctx, token); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	found, err := store.TokenByHash(ctx, signet.TokenResetPassword, "digest-1")
	if err != nil || found.ID != token.ID {
		t.Fatalf("TokenByHash = (%v, %v)", found, err)
	}
	consumed, err := store.ConsumeToken(ctx, signet.TokenResetPassword, "digest-1")
	if err != nil || consumed.ID != token.ID {
		t.Fatalf("ConsumeToken = (%v, %v)", consumed, err)
	}
	if _, err := store.ConsumeToken(ctx, signet.TokenResetPassword, "digest-1"); err == nil {
		t.Fatal("second ConsumeToken succeeded, want failure")
	}
	stillVisible, err := store.TokenByHash(ctx, signet.TokenResetPassword, "digest-1")
	if err != nil || stillVisible.UsedAt == nil {
		t.Fatalf("consumed Token should remain visible with UsedAt set: (%v, %v)", stillVisible, err)
	}
	if err := store.DeleteTokensForUser(ctx, "user-1", signet.TokenResetPassword); err != nil {
		t.Fatalf("DeleteTokensForUser: %v", err)
	}
	if _, err := store.TokenByHash(ctx, signet.TokenResetPassword, "digest-1"); !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("after DeleteTokensForUser error = %v, want ErrNotFound", err)
	}
}

func testTokenConcurrency(t *testing.T, store signet.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.CreateUser(ctx, &signet.User{ID: "user-1", Email: "user@example.com", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token := &signet.Token{
		ID: "token-1", UserID: "user-1", Kind: signet.TokenVerifyEmail,
		Hash: "digest-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := store.CreateToken(ctx, token); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	const callers = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.ConsumeToken(ctx, signet.TokenVerifyEmail, "digest-1"); err == nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("concurrent ConsumeToken winners = %d, want 1", winners)
	}
}
