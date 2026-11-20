// Package secret generates and digests the opaque tokens Signet issues.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// NewToken returns a 32-byte random token encoded for transport.
func NewToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("signet: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// Digest returns the SHA-256 hex digest of a raw token.
func Digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewID returns a 16-byte random identifier encoded as lowercase hex.
func NewID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("signet: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(buf)
}
