package signet

import (
	"context"

	"github.com/shakibdshy/signet/internal/session"
)

// ListSessionsInput selects the User whose Sessions should be listed.
type ListSessionsInput struct{ UserID string }

// ListSessionsResult contains the safe fields of a User's Sessions.
type ListSessionsResult struct{ Sessions []*SessionInfo }

// RevokeSessionInput identifies one Session to revoke.
type RevokeSessionInput struct{ SessionID string }

// RevokeAllSessionsInput identifies the User whose Sessions should be revoked.
type RevokeAllSessionsInput struct{ UserID string }

// SessionInfo is the safe representation of a Session.
type SessionInfo = session.Info

// ListSessions returns the Sessions belonging to a User.
func (c *Client) ListSessions(ctx context.Context, in ListSessionsInput) (*ListSessionsResult, error) {
	sessions, err := c.sessions.List(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	return &ListSessionsResult{Sessions: sessions}, nil
}

// RevokeSession revokes one Session. Unknown IDs are a no-op.
func (c *Client) RevokeSession(ctx context.Context, in RevokeSessionInput) error {
	return c.sessions.Revoke(ctx, in.SessionID)
}

// RevokeAllSessions revokes every Session of a User.
func (c *Client) RevokeAllSessions(ctx context.Context, in RevokeAllSessionsInput) error {
	return c.sessions.RevokeAll(ctx, in.UserID)
}
