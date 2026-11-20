// Package session implements Signet's session persistence and resolution.
package session

import (
	"context"
	"errors"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
)

// Service manages Sessions against a Store.
type Service struct {
	store core.Store
	clock core.Clock
	cfg   core.SessionConfig
}

// New returns a session Service.
func New(store core.Store, clock core.Clock, cfg core.SessionConfig) *Service {
	return &Service{store: store, clock: clock, cfg: cfg}
}

// Create issues a new opaque Session token and stores only its digest.
func (s *Service) Create(ctx context.Context, userID string) (string, error) {
	token := secret.NewToken()
	now := s.clock.Now()
	session := &core.Session{
		ID:                secret.NewID(),
		UserID:            userID,
		TokenHash:         secret.Digest(token),
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(s.cfg.IdleTimeout),
		AbsoluteExpiresAt: now.Add(s.cfg.AbsoluteTimeout),
	}
	if err := s.store.CreateSession(ctx, session); err != nil {
		return "", err
	}
	return token, nil
}

// Resolve returns the User for a raw Session token, enforcing idle and
// absolute deadlines and extending the idle window on success.
func (s *Service) Resolve(ctx context.Context, raw string) (*core.User, error) {
	if raw == "" {
		return nil, core.ErrNotFound
	}
	session, err := s.store.SessionByHash(ctx, secret.Digest(raw))
	if err != nil || session.RevokedAt != nil {
		return nil, core.ErrNotFound
	}
	now := s.clock.Now()
	if !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
		_ = s.store.DeleteSession(ctx, session.ID)
		return nil, core.ErrNotFound
	}
	user, err := s.store.UserByID(ctx, session.UserID)
	if err != nil || user.Disabled {
		return nil, core.ErrNotFound
	}
	_ = s.store.TouchSession(ctx, session.ID, now.Add(s.cfg.IdleTimeout))
	return user, nil
}

// Revoke revokes a Session by ID. Unknown IDs are a no-op.
func (s *Service) Revoke(ctx context.Context, id string) error {
	if err := s.store.DeleteSession(ctx, id); err != nil && !errors.Is(err, core.ErrNotFound) {
		return err
	}
	return nil
}

// RevokeAll revokes every Session of a User.
func (s *Service) RevokeAll(ctx context.Context, userID string) error {
	return s.store.DeleteSessionsForUser(ctx, userID)
}

// List returns the safe fields of a User's Sessions.
func (s *Service) List(ctx context.Context, userID string) ([]*core.SessionInfo, error) {
	sessions, err := s.store.ListSessionsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	info := make([]*core.SessionInfo, 0, len(sessions))
	for _, session := range sessions {
		info = append(info, &core.SessionInfo{
			ID: session.ID, CreatedAt: session.CreatedAt, LastSeenAt: session.LastSeenAt,
			IdleExpiresAt: session.IdleExpiresAt, AbsoluteExpiresAt: session.AbsoluteExpiresAt,
			RevokedAt: session.RevokedAt,
		})
	}
	return info, nil
}

// ByHash returns the Session for a raw token digest.
func (s *Service) ByHash(ctx context.Context, digest string) (*core.Session, error) {
	return s.store.SessionByHash(ctx, digest)
}
