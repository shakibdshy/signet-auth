// Package session implements Signet's session persistence and resolution.
package session

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/shakibdshy/signet-auth/internal/core"
	"github.com/shakibdshy/signet-auth/internal/secret"
)

// Service manages Sessions against a Store.
type Service struct {
	store  core.Store
	clock  core.Clock
	cfg    core.SessionConfig
	cache  core.SessionCache
	logger *slog.Logger
}

// New returns a session Service. cache may be nil to disable caching.
func New(store core.Store, clock core.Clock, cfg core.SessionConfig, cache core.SessionCache, logger *slog.Logger) *Service {
	return &Service{store: store, clock: clock, cfg: cfg, cache: cache, logger: logger}
}

func (s *Service) warn(event string, err error) {
	if s.logger != nil {
		s.logger.Warn(event, "error", err)
	}
}

func (s *Service) flush(ctx context.Context) {
	if s.cache == nil {
		return
	}
	if err := s.cache.Flush(ctx); err != nil {
		s.warn("session_cache_flush_failed", err)
	}
}

// Flush invalidates every cached Session. It is a no-op without a cache.
func (s *Service) Flush(ctx context.Context) {
	s.flush(ctx)
}

// Create issues a new opaque Session token and stores only its digest. The
// user agent of the request that started the visit, when known, identifies the
// Sign-in client on the Session.
func (s *Service) Create(ctx context.Context, userID, userAgent string) (string, error) {
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
		UserAgent:         core.TruncateUserAgent(userAgent),
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
	now := s.clock.Now()
	digest := secret.Digest(raw)
	if s.cache != nil && s.cfg.CacheTTL > 0 {
		cached, err := s.cache.Get(ctx, digest)
		if err != nil {
			s.warn("session_cache_get_failed", err)
		}
		if err == nil && cached != nil && cached.User != nil && !cached.User.Disabled &&
			now.Before(cached.IdleExpiresAt) && now.Before(cached.AbsoluteExpiresAt) {
			// Preserve sliding idle expiry: a cache hit still touches the Session.
			cached.IdleExpiresAt = now.Add(s.cfg.IdleTimeout)
			_ = s.store.TouchSession(ctx, cached.ID, cached.IdleExpiresAt)
			if err := s.cache.Put(ctx, digest, cached, s.cfg.CacheTTL); err != nil {
				s.warn("session_cache_put_failed", err)
			}
			return cached.User, nil
		}
	}
	session, err := s.store.SessionByHash(ctx, digest)
	if err != nil || session.RevokedAt != nil {
		return nil, core.ErrNotFound
	}
	if !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
		_ = s.store.DeleteSession(ctx, session.ID)
		s.flush(ctx)
		return nil, core.ErrNotFound
	}
	user, err := s.store.UserByID(ctx, session.UserID)
	if err != nil || user.Disabled {
		return nil, core.ErrNotFound
	}
	_ = s.store.TouchSession(ctx, session.ID, now.Add(s.cfg.IdleTimeout))
	if s.cache != nil && s.cfg.CacheTTL > 0 {
		ttl := s.cfg.CacheTTL
		if remaining := session.IdleExpiresAt.Sub(now); remaining < ttl {
			ttl = remaining
		}
		if remaining := session.AbsoluteExpiresAt.Sub(now); remaining < ttl {
			ttl = remaining
		}
		if ttl > 0 {
			if err := s.cache.Put(ctx, digest, &core.CachedSession{
				ID: session.ID, User: user, IdleExpiresAt: session.IdleExpiresAt,
				AbsoluteExpiresAt: session.AbsoluteExpiresAt,
			}, ttl); err != nil {
				s.warn("session_cache_put_failed", err)
			}
		}
	}
	return user, nil
}

// Revoke revokes a Session by ID. Unknown IDs are a no-op.
func (s *Service) Revoke(ctx context.Context, id string) error {
	if err := s.store.DeleteSession(ctx, id); err != nil && !errors.Is(err, core.ErrNotFound) {
		return err
	}
	s.flush(ctx)
	return nil
}

// RevokeAll revokes every Session of a User.
func (s *Service) RevokeAll(ctx context.Context, userID string) error {
	if err := s.store.DeleteSessionsForUser(ctx, userID); err != nil {
		return err
	}
	s.flush(ctx)
	return nil
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
			RevokedAt: session.RevokedAt, UserAgent: session.UserAgent,
		})
	}
	return info, nil
}

// IsFresh reports whether the Session was created within the configured window.
// A zero window disables freshness checks.
func (s *Service) IsFresh(ctx context.Context, raw string) (bool, error) {
	session, err := s.store.SessionByHash(ctx, secret.Digest(raw))
	if err != nil {
		return false, err
	}
	if s.cfg.FreshAge <= 0 {
		return true, nil
	}
	return s.clock.Now().Before(session.CreatedAt.Add(s.cfg.FreshAge)), nil
}

// IsFreshWithin reports whether the Session was created within an explicit
// window, independent of SessionConfig.FreshAge.
func (s *Service) IsFreshWithin(ctx context.Context, raw string, window time.Duration) (bool, error) {
	if window <= 0 {
		return true, nil
	}
	session, err := s.store.SessionByHash(ctx, secret.Digest(raw))
	if err != nil {
		return false, err
	}
	return s.clock.Now().Before(session.CreatedAt.Add(window)), nil
}

// ByHash returns the Session for a raw token digest.
func (s *Service) ByHash(ctx context.Context, digest string) (*core.Session, error) {
	return s.store.SessionByHash(ctx, digest)
}
