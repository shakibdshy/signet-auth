// Package testutil provides adapters and config builders for Signet's tests.
// Production code must not import it.
package testutil

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shakibdshy/signet-auth"
)

// ErrStore is the failure returned by a Store configured to fail account creation.
var ErrStore = errors.New("test store failure")

// Store is an in-memory signet.Store adapter.
type Store struct {
	Users             map[string]*signet.User
	UsersByEmail      map[string]*signet.User
	Accounts          []*signet.Account
	Sessions          map[string]*signet.Session
	Tokens            []*signet.Token
	FailAccountCreate bool
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{
		Users:        make(map[string]*signet.User),
		UsersByEmail: make(map[string]*signet.User),
		Sessions:     make(map[string]*signet.Session),
	}
}

// CreateUser implements signet.UserStore.
func (s *Store) CreateUser(_ context.Context, u *signet.User) error {
	if u.ID == "" {
		u.ID = "generated-id"
	}
	s.Users[u.ID] = u
	s.UsersByEmail[u.Email] = u
	return nil
}

// ListUsersForAdmin implements signet.AdminUserStore.
func (s *Store) ListUsersForAdmin(context.Context) ([]*signet.User, error) {
	out := make([]*signet.User, 0, len(s.Users))
	for _, user := range s.Users {
		out = append(out, user)
	}
	return out, nil
}

// UserByID implements signet.UserStore.
func (s *Store) UserByID(_ context.Context, id string) (*signet.User, error) {
	if u, ok := s.Users[id]; ok {
		return u, nil
	}
	return nil, signet.ErrNotFound
}

// UserByEmail implements signet.UserStore.
func (s *Store) UserByEmail(_ context.Context, email string) (*signet.User, error) {
	if u, ok := s.UsersByEmail[email]; ok {
		return u, nil
	}
	return nil, signet.ErrNotFound
}

// UpdateUser implements signet.UserStore.
func (s *Store) UpdateUser(_ context.Context, u *signet.User) error {
	s.Users[u.ID] = u
	s.UsersByEmail[u.Email] = u
	return nil
}

// DeleteUser implements signet.UserStore.
func (s *Store) DeleteUser(_ context.Context, id string) error {
	if u, ok := s.Users[id]; ok {
		delete(s.UsersByEmail, u.Email)
	}
	delete(s.Users, id)
	return nil
}

// CreateAccount implements signet.AccountStore.
func (s *Store) CreateAccount(_ context.Context, a *signet.Account) error {
	if s.FailAccountCreate {
		return ErrStore
	}
	if a.ID == "" {
		a.ID = "generated-account-id"
	}
	s.Accounts = append(s.Accounts, a)
	return nil
}

// AccountsForUser implements signet.AccountStore.
func (s *Store) AccountsForUser(_ context.Context, userID string) ([]*signet.Account, error) {
	var out []*signet.Account
	for _, a := range s.Accounts {
		if a.UserID == userID {
			out = append(out, a)
		}
	}
	return out, nil
}

// AccountByProvider implements signet.AccountStore.
func (s *Store) AccountByProvider(_ context.Context, provider, providerUserID string) (*signet.Account, error) {
	for _, a := range s.Accounts {
		if a.Provider == provider && a.ProviderUserID == providerUserID {
			return a, nil
		}
	}
	return nil, signet.ErrNotFound
}

// UpdateAccount implements signet.AccountStore.
func (s *Store) UpdateAccount(_ context.Context, a *signet.Account) error {
	for i, existing := range s.Accounts {
		if existing.ID == a.ID {
			s.Accounts[i] = a
			return nil
		}
	}
	return signet.ErrNotFound
}

// DeleteAccount implements signet.AccountStore.
func (s *Store) DeleteAccount(_ context.Context, id string) error {
	for i, a := range s.Accounts {
		if a.ID == id {
			s.Accounts = append(s.Accounts[:i], s.Accounts[i+1:]...)
			return nil
		}
	}
	return signet.ErrNotFound
}

// CreateSession implements signet.SessionStore.
func (s *Store) CreateSession(_ context.Context, session *signet.Session) error {
	s.Sessions[session.ID] = session
	return nil
}

// SessionByHash implements signet.SessionStore.
func (s *Store) SessionByHash(_ context.Context, hash string) (*signet.Session, error) {
	for _, session := range s.Sessions {
		if session.TokenHash == hash {
			return session, nil
		}
	}
	return nil, signet.ErrNotFound
}

// TouchSession implements signet.SessionStore.
func (s *Store) TouchSession(_ context.Context, id string, idleExpiresAt time.Time) error {
	if session, ok := s.Sessions[id]; ok {
		session.IdleExpiresAt = idleExpiresAt
		return nil
	}
	return signet.ErrNotFound
}

// DeleteSession implements signet.SessionStore.
func (s *Store) DeleteSession(_ context.Context, id string) error {
	delete(s.Sessions, id)
	return nil
}

// DeleteSessionsForUser implements signet.SessionStore.
func (s *Store) DeleteSessionsForUser(_ context.Context, userID string) error {
	for id, session := range s.Sessions {
		if session.UserID == userID {
			delete(s.Sessions, id)
		}
	}
	return nil
}

// ListSessionsForUser implements signet.SessionStore.
func (s *Store) ListSessionsForUser(_ context.Context, userID string) ([]*signet.Session, error) {
	var out []*signet.Session
	for _, session := range s.Sessions {
		if session.UserID == userID {
			out = append(out, session)
		}
	}
	return out, nil
}

// CreateToken implements signet.TokenStore.
func (s *Store) CreateToken(_ context.Context, token *signet.Token) error {
	s.Tokens = append(s.Tokens, token)
	return nil
}

// ConsumeToken implements signet.TokenStore.
func (s *Store) ConsumeToken(_ context.Context, kind signet.TokenKind, hash string) (*signet.Token, error) {
	token, err := s.TokenByHash(context.Background(), kind, hash)
	if err != nil || token.UsedAt != nil {
		return nil, signet.ErrNotFound
	}
	used := time.Now()
	token.UsedAt = &used
	return token, nil
}

// TokenByHash implements signet.TokenStore.
func (s *Store) TokenByHash(_ context.Context, kind signet.TokenKind, hash string) (*signet.Token, error) {
	for _, token := range s.Tokens {
		if token.Kind == kind && token.Hash == hash {
			return token, nil
		}
	}
	return nil, signet.ErrNotFound
}

// DeleteTokensForUser implements signet.TokenStore.
func (s *Store) DeleteTokensForUser(_ context.Context, userID string, kind signet.TokenKind) error {
	remaining := s.Tokens[:0]
	for _, token := range s.Tokens {
		if token.UserID != userID || token.Kind != kind {
			remaining = append(remaining, token)
		}
	}
	s.Tokens = remaining
	return nil
}

// Limiter is a recording signet.RateLimiter adapter.
type Limiter struct {
	Allowed bool
	Keys    []string
}

// NewLimiter returns a Limiter with the given allow decision.
func NewLimiter(allow bool) *Limiter { return &Limiter{Allowed: allow} }

// Allow implements signet.RateLimiter.
func (l *Limiter) Allow(_ context.Context, key string) (bool, error) {
	l.Keys = append(l.Keys, key)
	return l.Allowed, nil
}

// FastHasher is a deterministic, cheap PasswordHasher adapter.
type FastHasher struct{ Stale bool }

// Hash implements signet.PasswordHasher.
func (h FastHasher) Hash(_ context.Context, password string) (string, error) {
	return "encoded:" + password, nil
}

// Verify implements signet.PasswordHasher.
func (h FastHasher) Verify(_ context.Context, encoded, password string) (bool, error) {
	return encoded == "encoded:"+password, nil
}

// NeedsRehash implements signet.PasswordHasher.
func (h FastHasher) NeedsRehash(string) bool { return h.Stale }

// VersionedHasher is a PasswordHasher adapter that tracks parameter versions.
type VersionedHasher struct {
	Version     int
	VerifyCalls int
}

// Hash implements signet.PasswordHasher.
func (h *VersionedHasher) Hash(_ context.Context, password string) (string, error) {
	return fmt.Sprintf("v%d:%s", h.Version, password), nil
}

// Verify implements signet.PasswordHasher.
func (h *VersionedHasher) Verify(_ context.Context, encoded, password string) (bool, error) {
	h.VerifyCalls++
	parts := strings.SplitN(encoded, ":", 2)
	return len(parts) == 2 && parts[1] == password, nil
}

// NeedsRehash implements signet.PasswordHasher.
func (h *VersionedHasher) NeedsRehash(encoded string) bool {
	return !strings.HasPrefix(encoded, fmt.Sprintf("v%d:", h.Version))
}

// RehashFailureHasher fails rehash after the first two hashes.
type RehashFailureHasher struct{ Calls int }

// Hash implements signet.PasswordHasher.
func (h *RehashFailureHasher) Hash(_ context.Context, password string) (string, error) {
	h.Calls++
	if h.Calls > 2 {
		return "", ErrStore
	}
	return "v1:" + password, nil
}

// Verify implements signet.PasswordHasher.
func (h *RehashFailureHasher) Verify(_ context.Context, encoded, password string) (bool, error) {
	return strings.HasSuffix(encoded, ":"+password), nil
}

// NeedsRehash implements signet.PasswordHasher.
func (h *RehashFailureHasher) NeedsRehash(string) bool { return true }

// FixedClock is a Clock adapter with an immutable time.
type FixedClock struct{ At time.Time }

// Now implements signet.Clock.
func (c FixedClock) Now() time.Time { return c.At }

// Clock is a Clock adapter with a mutable time.
type Clock struct{ At time.Time }

// Now implements signet.Clock.
func (c *Clock) Now() time.Time { return c.At }

// Mailer is a recording signet.Mailer adapter.
type Mailer struct {
	Messages []signet.Message
	Fail     bool
}

// NewMailer returns an empty Mailer.
func NewMailer() *Mailer { return &Mailer{} }

// Send implements signet.Mailer.
func (m *Mailer) Send(_ context.Context, msg signet.Message) error {
	if m.Fail {
		return ErrStore
	}
	m.Messages = append(m.Messages, msg)
	return nil
}

// NewConfig returns a Config with verification disabled and a CSRF key, for tests.
func NewConfig() signet.Config {
	cfg := signet.DefaultConfig()
	cfg.RequireVerifiedEmail = BoolPtr(false)
	cfg.SendVerificationOnSignUp = BoolPtr(false)
	cfg.CSRFKey = make([]byte, 32)
	return cfg
}

// BoolPtr returns a pointer to value.
func BoolPtr(value bool) *bool { return &value }
