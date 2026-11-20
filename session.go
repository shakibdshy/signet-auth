package signet

import "time"

// Session is one authenticated visit by a User, with its own idle and
// absolute lifetimes. The raw session secret is never persisted; TokenHash
// holds the digest used to look a Session up.
type Session struct {
	ID                string
	UserID            string
	TokenHash         string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
}
