package signet

import (
	"context"
	"errors"
	"time"
)

// ListSessionsInput selects the User whose Sessions should be listed.
type ListSessionsInput struct {
	UserID string
}

// ListSessionsResult contains the safe fields of a User's Sessions.
type ListSessionsResult struct {
	Sessions []*SessionInfo
}

// RevokeSessionInput identifies one Session to revoke.
type RevokeSessionInput struct {
	SessionID string
}

// RevokeAllSessionsInput identifies the User whose Sessions should be revoked.
type RevokeAllSessionsInput struct {
	UserID string
}

// SessionInfo is the safe representation of a Session returned to callers. It
// never includes a token digest or the owner's identifier.
type SessionInfo struct {
	ID                string     `json:"id"`
	CreatedAt         time.Time  `json:"created_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	IdleExpiresAt     time.Time  `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time  `json:"absolute_expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
}

// ListSessions returns the Sessions belonging to a User.
func (c *Client) ListSessions(ctx context.Context, in ListSessionsInput) (*ListSessionsResult, error) {
	sessions, err := c.cfg.Store.ListSessionsForUser(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	info := make([]*SessionInfo, 0, len(sessions))
	for _, session := range sessions {
		info = append(info, &SessionInfo{
			ID:                session.ID,
			CreatedAt:         session.CreatedAt,
			LastSeenAt:        session.LastSeenAt,
			IdleExpiresAt:     session.IdleExpiresAt,
			AbsoluteExpiresAt: session.AbsoluteExpiresAt,
			RevokedAt:         session.RevokedAt,
		})
	}
	return &ListSessionsResult{Sessions: info}, nil
}

// RevokeSession revokes one Session. Unknown Session IDs are a no-op.
func (c *Client) RevokeSession(ctx context.Context, in RevokeSessionInput) error {
	if err := c.cfg.Store.DeleteSession(ctx, in.SessionID); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

// RevokeAllSessions revokes every Session belonging to a User.
func (c *Client) RevokeAllSessions(ctx context.Context, in RevokeAllSessionsInput) error {
	return c.cfg.Store.DeleteSessionsForUser(ctx, in.UserID)
}
