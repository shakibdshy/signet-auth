package signet

import (
	"context"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
)

// Session is one authenticated visit by a User, with its own idle and
// absolute lifetimes. The raw session secret is never persisted; TokenHash
// holds the digest used to look a Session up.
type Session = core.Session

func newRawSecret() (string, string) {
	token := secret.NewToken()
	return token, secret.Digest(token)
}

func (c *Client) createSession(ctx context.Context, userID string) (string, error) {
	token, digest := newRawSecret()
	now := c.cfg.Clock.Now()
	session := &Session{
		ID:                newID(),
		UserID:            userID,
		TokenHash:         digest,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(c.cfg.Session.IdleTimeout),
		AbsoluteExpiresAt: now.Add(c.cfg.Session.AbsoluteTimeout),
	}
	if err := c.cfg.Store.CreateSession(ctx, session); err != nil {
		return "", err
	}
	return token, nil
}

func digestSecret(token string) string { return secret.Digest(token) }
