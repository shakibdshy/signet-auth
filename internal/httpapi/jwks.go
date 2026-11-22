package httpapi

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"

	"github.com/shakibdshy/signet/internal/token"
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

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// JWKSHandler publishes only the public half of asymmetric signing keys. It is
// opt-in and is never mounted by Handler.
func JWKSHandler(keys []any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		out := make([]jsonWebKey, 0, len(keys))
		for _, key := range keys {
			public, err := token.PublicKey(key)
			if err != nil {
				continue
			}
			kid, err := token.KeyID(key)
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
		writeJSON(w, http.StatusOK, map[string]any{"keys": out})
	})
}
