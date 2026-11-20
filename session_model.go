package signet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/shakibdshy/signet/internal/core"
)

// Session is one authenticated visit by a User, with its own idle and
// absolute lifetimes. The raw session secret is never persisted; TokenHash
// holds the digest used to look a Session up.
type Session = core.Session

func newRawSecret() (string, string) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("signet: crypto/rand unavailable: " + err.Error())
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	digest := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(digest[:])
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

func digestSecret(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
