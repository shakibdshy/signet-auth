package signet

import (
	"context"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
)

// Session is one authenticated visit by a User.
type Session = core.Session

func newRawSecret() (string, string) {
	token := secret.NewToken()
	return token, secret.Digest(token)
}

func (c *Client) createSession(ctx context.Context, userID string) (string, error) {
	return c.sessions.Create(ctx, userID)
}

func digestSecret(token string) string { return secret.Digest(token) }
