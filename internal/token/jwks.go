package token

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"

	"github.com/shakibdshy/signet/internal/core"
)

// PublicKey returns the public half of a signing key in the supported ring.
func PublicKey(key any) (any, error) {
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		return &typed.PublicKey, nil
	case *rsa.PublicKey:
		return typed, nil
	case rsa.PublicKey:
		return &typed, nil
	case ed25519.PrivateKey:
		return typed.Public(), nil
	case ed25519.PublicKey:
		return typed, nil
	default:
		return nil, core.ErrInvalidJWTKey
	}
}

// KeyID derives a stable identifier for a signing key from its public encoding.
func KeyID(key any) (string, error) {
	public, err := PublicKey(key)
	if err != nil {
		return "", err
	}
	encoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
