package signet_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/auth"
	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/testutil"
	"github.com/shakibdshy/signet/internal/token"
)

var (
	_ signet.Store                                                  = (*testutil.Store)(nil)
	_                                                               = errors.Is(signet.ErrNotFound, core.ErrNotFound)
	_                                                               = errors.Is(signet.ErrMissingHasher, core.ErrMissingHasher)
	_ func(*core.JWTConfig) error                                   = token.ValidateJWTConfig
	_ func(token.JWTDependencies) *token.JWTService                 = token.NewJWT
	_ auth.Argon2idHasher                                           = signet.Argon2idHasher{}
	_ func(auth.VerificationDependencies) *auth.VerificationService = auth.NewVerification
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
func (fakeTokenStore) TokenByHash(context.Context, signet.TokenKind, string) (*signet.Token, error) {
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

// TestRootSentinelsMatchCore guards the public sentinel surface: every root
// error must stay bound to its private core value so errors.Is keeps working.
func TestRootSentinelsMatchCore(t *testing.T) {
	pairs := []struct {
		name string
		root error
		core error
	}{
		{"ErrNotFound", signet.ErrNotFound, core.ErrNotFound},
		{"ErrInvalidCredentials", signet.ErrInvalidCredentials, core.ErrInvalidCredentials},
		{"ErrEmailNotVerified", signet.ErrEmailNotVerified, core.ErrEmailNotVerified},
		{"ErrRateLimited", signet.ErrRateLimited, core.ErrRateLimited},
		{"ErrTokenExpired", signet.ErrTokenExpired, core.ErrTokenExpired},
		{"ErrTokenInvalid", signet.ErrTokenInvalid, core.ErrTokenInvalid},
		{"ErrMissingStore", signet.ErrMissingStore, core.ErrMissingStore},
		{"ErrMissingMailer", signet.ErrMissingMailer, core.ErrMissingMailer},
		{"ErrMissingHasher", signet.ErrMissingHasher, core.ErrMissingHasher},
		{"ErrMissingRateLimiter", signet.ErrMissingRateLimiter, core.ErrMissingRateLimiter},
		{"ErrInsecureConfig", signet.ErrInsecureConfig, core.ErrInsecureConfig},
		{"ErrInvalidEmail", signet.ErrInvalidEmail, core.ErrInvalidEmail},
		{"ErrPasswordTooShort", signet.ErrPasswordTooShort, core.ErrPasswordTooShort},
		{"ErrPasswordTooLong", signet.ErrPasswordTooLong, core.ErrPasswordTooLong},
		{"ErrEmailAlreadyExists", signet.ErrEmailAlreadyExists, core.ErrEmailAlreadyExists},
		{"ErrJWTDisabled", signet.ErrJWTDisabled, core.ErrJWTDisabled},
		{"ErrInvalidJWTAlgorithm", signet.ErrInvalidJWTAlgorithm, core.ErrInvalidJWTAlgorithm},
		{"ErrInvalidJWTKey", signet.ErrInvalidJWTKey, core.ErrInvalidJWTKey},
		{"ErrRefreshReuse", signet.ErrRefreshReuse, core.ErrRefreshReuse},
		{"ErrInvalidOAuthConfig", signet.ErrInvalidOAuthConfig, core.ErrInvalidOAuthConfig},
		{"ErrOAuthDisabled", signet.ErrOAuthDisabled, core.ErrOAuthDisabled},
		{"ErrOAuthProviderNotFound", signet.ErrOAuthProviderNotFound, core.ErrOAuthProviderNotFound},
		{"ErrOAuthInvalidState", signet.ErrOAuthInvalidState, core.ErrOAuthInvalidState},
		{"ErrOAuthRedirectNotAllowed", signet.ErrOAuthRedirectNotAllowed, core.ErrOAuthRedirectNotAllowed},
		{"ErrOAuthEmailNotVerified", signet.ErrOAuthEmailNotVerified, core.ErrOAuthEmailNotVerified},
		{"ErrOAuthAccountConflict", signet.ErrOAuthAccountConflict, core.ErrOAuthAccountConflict},
		{"ErrInvalidCSRFConfig", signet.ErrInvalidCSRFConfig, core.ErrInvalidCSRFConfig},
	}
	for _, pair := range pairs {
		if !errors.Is(pair.root, pair.core) {
			t.Errorf("root sentinel %s is not bound to core", pair.name)
		}
	}
}
