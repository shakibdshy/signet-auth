package signet_test

import (
	"context"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
)

type fakeUserStore struct{}

func (fakeUserStore) CreateUser(context.Context, *signet.User) error         { return nil }
func (fakeUserStore) UserByID(context.Context, string) (*signet.User, error) { return nil, nil }
func (fakeUserStore) UserByEmail(context.Context, string) (*signet.User, error) {
	return nil, nil
}
func (fakeUserStore) UpdateUser(context.Context, *signet.User) error { return nil }
func (fakeUserStore) DeleteUser(context.Context, string) error       { return nil }

type fakeAccountStore struct{}

func (fakeAccountStore) CreateAccount(context.Context, *signet.Account) error { return nil }
func (fakeAccountStore) AccountsForUser(context.Context, string) ([]*signet.Account, error) {
	return nil, nil
}
func (fakeAccountStore) AccountByProvider(context.Context, string, string) (*signet.Account, error) {
	return nil, nil
}
func (fakeAccountStore) UpdateAccount(context.Context, *signet.Account) error { return nil }
func (fakeAccountStore) DeleteAccount(context.Context, string) error          { return nil }

type fakeSessionStore struct{}

func (fakeSessionStore) CreateSession(context.Context, *signet.Session) error { return nil }
func (fakeSessionStore) SessionByHash(context.Context, string) (*signet.Session, error) {
	return nil, nil
}
func (fakeSessionStore) TouchSession(context.Context, string, time.Time) error { return nil }
func (fakeSessionStore) DeleteSession(context.Context, string) error           { return nil }
func (fakeSessionStore) DeleteSessionsForUser(context.Context, string) error   { return nil }
func (fakeSessionStore) ListSessionsForUser(context.Context, string) ([]*signet.Session, error) {
	return nil, nil
}

type fakeTokenStore struct{}

func (fakeTokenStore) CreateToken(context.Context, *signet.Token) error { return nil }
func (fakeTokenStore) ConsumeToken(context.Context, signet.TokenKind, string) (*signet.Token, error) {
	return nil, nil
}
func (fakeTokenStore) DeleteTokensForUser(context.Context, string, signet.TokenKind) error {
	return nil
}

type fakeStore struct {
	fakeUserStore
	fakeAccountStore
	fakeSessionStore
	fakeTokenStore
}

type fakeMailer struct{}

func (fakeMailer) Send(context.Context, signet.Message) error { return nil }

type fakePasswordHasher struct{}

func (fakePasswordHasher) Hash(context.Context, string) (string, error) { return "", nil }
func (fakePasswordHasher) Verify(context.Context, string, string) (bool, error) {
	return false, nil
}
func (fakePasswordHasher) NeedsRehash(string) bool { return false }

type fakeRateLimiter struct{}

func (fakeRateLimiter) Allow(context.Context, string) (bool, error) { return false, nil }

var (
	_ signet.Store          = (*fakeStore)(nil)
	_ signet.UserStore      = (*fakeUserStore)(nil)
	_ signet.AccountStore   = (*fakeAccountStore)(nil)
	_ signet.SessionStore   = (*fakeSessionStore)(nil)
	_ signet.TokenStore     = (*fakeTokenStore)(nil)
	_ signet.Mailer         = fakeMailer{}
	_ signet.PasswordHasher = fakePasswordHasher{}
	_ signet.RateLimiter    = fakeRateLimiter{}
	_ signet.Clock          = signet.SystemClock{}
)

func TestStoreContractIsUsable(t *testing.T) {
	var store signet.Store = &fakeStore{}
	user := &signet.User{ID: "user-1", Email: "user@example.com"}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
}

func TestTokenKindValues(t *testing.T) {
	tests := []struct {
		got  signet.TokenKind
		want string
	}{
		{signet.TokenVerifyEmail, "verify_email"},
		{signet.TokenResetPassword, "reset_password"},
		{signet.TokenOAuthLink, "oauth_link"},
	}
	for _, tt := range tests {
		if string(tt.got) != tt.want {
			t.Errorf("TokenKind = %q, want %q", tt.got, tt.want)
		}
	}
}

func TestSystemClock(t *testing.T) {
	before := time.Now()
	got := (signet.SystemClock{}).Now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Fatalf("Now() = %v, want a time between %v and %v", got, before, after)
	}
}
