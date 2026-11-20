package signet

import (
	"context"

	"github.com/shakibdshy/signet/internal/core"
)

// ListSessionsInput selects the User whose Sessions should be listed.
type ListSessionsInput = core.ListSessionsInput

// ListSessionsResult contains the safe fields of a User's Sessions.
type ListSessionsResult = core.ListSessionsResult

// RevokeSessionInput identifies one Session to revoke.
type RevokeSessionInput = core.RevokeSessionInput

// RevokeAllSessionsInput identifies the User whose Sessions should be revoked.
type RevokeAllSessionsInput = core.RevokeAllSessionsInput

// SessionInfo is the safe representation of a Session.
type SessionInfo = core.SessionInfo

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
