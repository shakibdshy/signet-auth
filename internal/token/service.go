// Package token issues and consumes Signet's single-use proofs.
package token

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
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

// IssueWithData stores a single-use proof whose raw value also carries opaque
// application data. The digest stored in the Token still covers the full raw
// value, so modifying the embedded data invalidates the proof.
func (s *Service) IssueWithData(ctx context.Context, userID string, kind core.TokenKind, ttl time.Duration, data string) (string, *core.Token, error) {
	raw := secret.NewToken() + "." + base64.RawURLEncoding.EncodeToString([]byte(data))
	now := s.clock.Now()
	token := &core.Token{
		ID: secret.NewID(), UserID: userID, Kind: kind, Hash: secret.Digest(raw),
		ExpiresAt: now.Add(ttl), CreatedAt: now,
	}
	if err := s.store.CreateToken(ctx, token); err != nil {
		return "", nil, err
	}
	return raw, token, nil
}

// ByHash looks up a Token without consuming it. It rejects used and expired
// proofs so a caller can validate an input before claiming the Token.
func (s *Service) ByHash(ctx context.Context, kind core.TokenKind, raw string) (*core.Token, error) {
	digest := secret.Digest(raw)
	token, err := s.store.TokenByHash(ctx, kind, digest)
	if errors.Is(err, core.ErrNotFound) {
		return nil, core.ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	if token.UsedAt != nil {
		return nil, core.ErrTokenConsumed
	}
	if !s.clock.Now().Before(token.ExpiresAt) {
		return nil, core.ErrTokenExpired
	}
	return token, nil
}

// ParseData extracts the opaque data embedded by IssueWithData.
func ParseData(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return "", fmt.Errorf("malformed proof")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	return string(data), nil
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
		return nil, core.ErrTokenConsumed
	}
	if !s.clock.Now().Before(token.ExpiresAt) {
		return nil, core.ErrTokenExpired
	}
	consumed, err := s.store.ConsumeToken(ctx, kind, digest)
	if errors.Is(err, core.ErrNotFound) {
		// A concurrent consume won the race; the proof is no longer usable.
		return nil, core.ErrTokenConsumed
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
