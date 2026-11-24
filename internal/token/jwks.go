package token

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"

	"github.com/shakibdshy/signet-auth/internal/core"
)

type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

func publicKey(key any) (any, error) {
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

func keyID(key any) (string, error) {
	public, err := publicKey(key)
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

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// JWKS builds the public key document for the asymmetric keys in a ring.
// No private key material is included.
func JWKS(keys []any) ([]byte, error) {
	out := make([]jsonWebKey, 0, len(keys))
	for _, key := range keys {
		public, err := publicKey(key)
		if err != nil {
			continue
		}
		kid, err := keyID(key)
		if err != nil {
			continue
		}
		switch typed := public.(type) {
		case *rsa.PublicKey:
			out = append(out, jsonWebKey{
				Kty: "RSA", Kid: kid, Alg: "RS256", Use: "sig",
				N: encode(typed.N.Bytes()),
				E: encode(big.NewInt(int64(typed.E)).Bytes()),
			})
		case ed25519.PublicKey:
			out = append(out, jsonWebKey{
				Kty: "OKP", Kid: kid, Alg: "EdDSA", Use: "sig", Crv: "Ed25519", X: encode(typed),
			})
		}
	}
	return json.Marshal(map[string]any{"keys": out})
}
