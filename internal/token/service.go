// Package token issues and consumes Signet's single-use proofs.
package token

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
)

// Service issues and consumes one-time Tokens against a TokenStore.
type Service struct {
	store core.TokenStore
	clock core.Clock
}

// New returns a Service backed by store and clock.
func New(store core.TokenStore, clock core.Clock) *Service {
	return &Service{store: store, clock: clock}
}

// Issue stores a fresh Token and returns its raw proof.
func (s *Service) Issue(ctx context.Context, userID string, kind core.TokenKind, ttl time.Duration) (string, *core.Token, error) {
	raw := secret.NewToken()
	now := s.clock.Now()
	token := &core.Token{
		ID:        secret.NewID(),
		UserID:    userID,
		Kind:      kind,
		Hash:      secret.Digest(raw),
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	if err := s.store.CreateToken(ctx, token); err != nil {
		return "", nil, err
	}
	return raw, token, nil
}

// Consume atomically claims an unused Token. A replay or expired proof fails.
func (s *Service) Consume(ctx context.Context, kind core.TokenKind, raw string) (*core.Token, error) {
	digest := secret.Digest(raw)
	token, err := s.store.TokenByHash(ctx, kind, digest)
	if errors.Is(err, core.ErrNotFound) {
		return nil, core.ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	if token.UsedAt != nil {
		return nil, core.ErrTokenInvalid
	}
	if !s.clock.Now().Before(token.ExpiresAt) {
		return nil, core.ErrTokenExpired
	}
	consumed, err := s.store.ConsumeToken(ctx, kind, digest)
	if errors.Is(err, core.ErrNotFound) {
		return nil, core.ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	// Compare in constant time even though the store already matched the digest.
	if subtle.ConstantTimeCompare([]byte(consumed.Hash), []byte(digest)) != 1 {
		return nil, core.ErrTokenInvalid
	}
	return consumed, nil
}
