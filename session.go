package signet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
)

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

func newSessionToken() (string, string) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("signet: crypto/rand unavailable: " + err.Error())
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	digest := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(digest[:])
}

func digestSessionToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
