package signet_test

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shakibdshy/signet"
)

type memoryStore struct {
	users             map[string]*signet.User
	usersByEmail      map[string]*signet.User
	accounts          []*signet.Account
	sessions          map[string]*signet.Session
	tokens            []*signet.Token
	failAccountCreate bool
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		users:        make(map[string]*signet.User),
		usersByEmail: make(map[string]*signet.User),
		sessions:     make(map[string]*signet.Session),
	}
}

func (s *memoryStore) CreateUser(_ context.Context, u *signet.User) error {
	if u.ID == "" {
		u.ID = "generated-id"
	}
	s.users[u.ID] = u
	s.usersByEmail[u.Email] = u
	return nil
}
func (s *memoryStore) UserByID(_ context.Context, id string) (*signet.User, error) {
	if u, ok := s.users[id]; ok {
		return u, nil
	}
	return nil, signet.ErrNotFound
}
func (s *memoryStore) UserByEmail(_ context.Context, email string) (*signet.User, error) {
	if u, ok := s.usersByEmail[email]; ok {
		return u, nil
	}
	return nil, signet.ErrNotFound
}
func (s *memoryStore) UpdateUser(_ context.Context, u *signet.User) error {
	s.users[u.ID] = u
	s.usersByEmail[u.Email] = u
	return nil
}
func (s *memoryStore) DeleteUser(_ context.Context, id string) error {
	if u, ok := s.users[id]; ok {
		delete(s.usersByEmail, u.Email)
	}
	delete(s.users, id)
	return nil
}

func (s *memoryStore) CreateAccount(_ context.Context, a *signet.Account) error {
	if s.failAccountCreate {
		return errTestStore
	}
	if a.ID == "" {
		a.ID = "generated-account-id"
	}
	s.accounts = append(s.accounts, a)
	return nil
}
func (s *memoryStore) AccountsForUser(_ context.Context, userID string) ([]*signet.Account, error) {
	var out []*signet.Account
	for _, a := range s.accounts {
		if a.UserID == userID {
			out = append(out, a)
		}
	}
	return out, nil
}
func (s *memoryStore) AccountByProvider(_ context.Context, provider, providerUserID string) (*signet.Account, error) {
	for _, a := range s.accounts {
		if a.Provider == provider && a.ProviderUserID == providerUserID {
			return a, nil
		}
	}
	return nil, signet.ErrNotFound
}
func (s *memoryStore) UpdateAccount(_ context.Context, a *signet.Account) error {
	for i, existing := range s.accounts {
		if existing.ID == a.ID {
			s.accounts[i] = a
			return nil
		}
	}
	return signet.ErrNotFound
}
func (s *memoryStore) DeleteAccount(_ context.Context, id string) error {
	for i, a := range s.accounts {
		if a.ID == id {
			s.accounts = append(s.accounts[:i], s.accounts[i+1:]...)
			return nil
		}
	}
	return signet.ErrNotFound
}

func (s *memoryStore) CreateSession(_ context.Context, session *signet.Session) error {
	s.sessions[session.ID] = session
	return nil
}
func (s *memoryStore) SessionByHash(_ context.Context, hash string) (*signet.Session, error) {
	for _, session := range s.sessions {
		if session.TokenHash == hash {
			return session, nil
		}
	}
	return nil, signet.ErrNotFound
}
func (s *memoryStore) TouchSession(_ context.Context, id string, idleExpiresAt time.Time) error {
	if session, ok := s.sessions[id]; ok {
		session.IdleExpiresAt = idleExpiresAt
		return nil
	}
	return signet.ErrNotFound
}
func (s *memoryStore) DeleteSession(_ context.Context, id string) error {
	delete(s.sessions, id)
	return nil
}
func (s *memoryStore) DeleteSessionsForUser(_ context.Context, userID string) error {
	for id, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}
func (s *memoryStore) ListSessionsForUser(_ context.Context, userID string) ([]*signet.Session, error) {
	var out []*signet.Session
	for _, session := range s.sessions {
		if session.UserID == userID {
			out = append(out, session)
		}
	}
	return out, nil
}

func (s *memoryStore) CreateToken(_ context.Context, token *signet.Token) error {
	s.tokens = append(s.tokens, token)
	return nil
}
func (s *memoryStore) ConsumeToken(_ context.Context, kind signet.TokenKind, hash string) (*signet.Token, error) {
	token, err := s.TokenByHash(context.Background(), kind, hash)
	if err != nil || token.UsedAt != nil {
		return nil, signet.ErrNotFound
	}
	used := time.Now()
	token.UsedAt = &used
	return token, nil
}
func (s *memoryStore) TokenByHash(_ context.Context, kind signet.TokenKind, hash string) (*signet.Token, error) {
	for _, token := range s.tokens {
		if token.Kind == kind && token.Hash == hash {
			return token, nil
		}
	}
	return nil, signet.ErrNotFound
}
func (s *memoryStore) DeleteTokensForUser(_ context.Context, userID string, kind signet.TokenKind) error {
	remaining := s.tokens[:0]
	for _, token := range s.tokens {
		if token.UserID != userID || token.Kind != kind {
			remaining = append(remaining, token)
		}
	}
	s.tokens = remaining
	return nil
}

type recordingLimiter struct {
	allow bool
	keys  []string
}

func (l *recordingLimiter) Allow(_ context.Context, key string) (bool, error) {
	l.keys = append(l.keys, key)
	return l.allow, nil
}

type fastHasher struct {
	stale bool
}

func (h fastHasher) Hash(_ context.Context, password string) (string, error) {
	return "encoded:" + password, nil
}
func (h fastHasher) Verify(_ context.Context, encoded, password string) (bool, error) {
	return encoded == "encoded:"+password, nil
}
func (h fastHasher) NeedsRehash(string) bool { return h.stale }

type versionedHasher struct {
	version     int
	verifyCalls int
}

func (h *versionedHasher) Hash(_ context.Context, password string) (string, error) {
	return fmt.Sprintf("v%d:%s", h.version, password), nil
}
func (h *versionedHasher) Verify(_ context.Context, encoded, password string) (bool, error) {
	h.verifyCalls++
	parts := strings.SplitN(encoded, ":", 2)
	return len(parts) == 2 && parts[1] == password, nil
}
func (h *versionedHasher) NeedsRehash(encoded string) bool {
	return !strings.HasPrefix(encoded, fmt.Sprintf("v%d:", h.version))
}

type rehashFailureHasher struct{ calls int }

func (h *rehashFailureHasher) Hash(_ context.Context, password string) (string, error) {
	h.calls++
	if h.calls > 2 {
		return "", errTestStore
	}
	return "v1:" + password, nil
}
func (h *rehashFailureHasher) Verify(_ context.Context, encoded, password string) (bool, error) {
	return strings.HasSuffix(encoded, ":"+password), nil
}
func (h *rehashFailureHasher) NeedsRehash(string) bool { return true }

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

type adjustableClock struct{ at time.Time }

func (c *adjustableClock) Now() time.Time { return c.at }

type capturingMailer struct {
	messages []signet.Message
	fail     bool
}

func (m *capturingMailer) Send(_ context.Context, msg signet.Message) error {
	if m.fail {
		return errTestStore
	}
	m.messages = append(m.messages, msg)
	return nil
}

func testConfig() signet.Config {
	cfg := signet.DefaultConfig()
	cfg.RequireVerifiedEmail = boolPtr(false)
	cfg.SendVerificationOnSignUp = boolPtr(false)
	cfg.CSRFKey = make([]byte, 32)
	return cfg
}

func boolPtr(value bool) *bool { return &value }

var errTestStore = &testStoreError{}

type testStoreError struct{}

func (*testStoreError) Error() string { return "test store failure" }
