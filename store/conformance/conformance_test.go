package conformance_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/store/conformance"
)

type referenceStore struct {
	mu       sync.Mutex
	users    map[string]*signet.User
	accounts map[string]*signet.Account
	sessions map[string]*signet.Session
	tokens   map[string]*signet.Token
}

func newReferenceStore() *referenceStore {
	return &referenceStore{
		users: make(map[string]*signet.User), accounts: make(map[string]*signet.Account),
		sessions: make(map[string]*signet.Session), tokens: make(map[string]*signet.Token),
	}
}

func (s *referenceStore) CreateUser(_ context.Context, u *signet.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.ID] = cloneUser(u)
	return nil
}
func (s *referenceStore) UserByID(_ context.Context, id string) (*signet.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[id]; ok {
		return cloneUser(u), nil
	}
	return nil, signet.ErrNotFound
}
func (s *referenceStore) UserByEmail(_ context.Context, email string) (*signet.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Email == email {
			return cloneUser(u), nil
		}
	}
	return nil, signet.ErrNotFound
}
func (s *referenceStore) UpdateUser(_ context.Context, u *signet.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.ID] = cloneUser(u)
	return nil
}
func (s *referenceStore) DeleteUser(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, id)
	return nil
}

func (s *referenceStore) CreateAccount(_ context.Context, a *signet.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	duplicate := *a
	s.accounts[a.ID] = &duplicate
	return nil
}
func (s *referenceStore) AccountsForUser(_ context.Context, userID string) ([]*signet.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*signet.Account
	for _, a := range s.accounts {
		if a.UserID == userID {
			duplicate := *a
			out = append(out, &duplicate)
		}
	}
	return out, nil
}
func (s *referenceStore) AccountByProvider(_ context.Context, provider, providerUserID string) (*signet.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Provider == provider && a.ProviderUserID == providerUserID {
			duplicate := *a
			return &duplicate, nil
		}
	}
	return nil, signet.ErrNotFound
}
func (s *referenceStore) UpdateAccount(_ context.Context, a *signet.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	duplicate := *a
	s.accounts[a.ID] = &duplicate
	return nil
}
func (s *referenceStore) DeleteAccount(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accounts, id)
	return nil
}

func (s *referenceStore) CreateSession(_ context.Context, session *signet.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	duplicate := *session
	s.sessions[session.ID] = &duplicate
	return nil
}
func (s *referenceStore) SessionByHash(_ context.Context, hash string) (*signet.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, session := range s.sessions {
		if session.TokenHash == hash {
			duplicate := *session
			return &duplicate, nil
		}
	}
	return nil, signet.ErrNotFound
}
func (s *referenceStore) TouchSession(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, ok := s.sessions[id]; ok {
		session.IdleExpiresAt = at
		return nil
	}
	return signet.ErrNotFound
}
func (s *referenceStore) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}
func (s *referenceStore) DeleteSessionsForUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}
func (s *referenceStore) ListSessionsForUser(_ context.Context, userID string) ([]*signet.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*signet.Session
	for _, session := range s.sessions {
		if session.UserID == userID {
			duplicate := *session
			out = append(out, &duplicate)
		}
	}
	return out, nil
}

func (s *referenceStore) CreateToken(_ context.Context, token *signet.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	duplicate := *token
	s.tokens[token.ID] = &duplicate
	return nil
}
func (s *referenceStore) TokenByHash(_ context.Context, kind signet.TokenKind, hash string) (*signet.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, token := range s.tokens {
		if token.Kind == kind && token.Hash == hash {
			duplicate := *token
			return &duplicate, nil
		}
	}
	return nil, signet.ErrNotFound
}
func (s *referenceStore) ConsumeToken(_ context.Context, kind signet.TokenKind, hash string) (*signet.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, token := range s.tokens {
		if token.Kind == kind && token.Hash == hash && token.UsedAt == nil {
			now := time.Now()
			token.UsedAt = &now
			duplicate := *token
			return &duplicate, nil
		}
	}
	return nil, signet.ErrNotFound
}
func (s *referenceStore) DeleteTokensForUser(_ context.Context, userID string, kind signet.TokenKind) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, token := range s.tokens {
		if token.UserID == userID && token.Kind == kind {
			delete(s.tokens, id)
		}
	}
	return nil
}

func cloneUser(u *signet.User) *signet.User { duplicate := *u; return &duplicate }

func TestReferenceStorePassesConformance(t *testing.T) {
	conformance.Run(t, func(*testing.T) signet.Store { return newReferenceStore() })
}
