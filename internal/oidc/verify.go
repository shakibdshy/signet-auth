package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const keySetTTL = 5 * time.Minute

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

// KeySet caches the public keys published by a Provider.
type KeySet struct {
	client  *http.Client
	uri     string
	mu      chan struct{}
	keys    map[string]any
	fetched time.Time
}

// NewKeySet returns a cache for the given JWKS URI.
func NewKeySet(client *http.Client, uri string) *KeySet {
	return &KeySet{client: client, uri: uri, mu: make(chan struct{}, 1), keys: make(map[string]any)}
}

func decodeSegment(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func parseKey(key jwk) (any, error) {
	switch key.Kty {
	case "RSA":
		n, err := decodeSegment(key.N)
		if err != nil {
			return nil, err
		}
		e, err := decodeSegment(key.E)
		if err != nil || len(e) == 0 {
			return nil, errors.New("oidc: invalid RSA exponent")
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 + int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}, nil
	case "EC":
		x, xErr := decodeSegment(key.X)
		y, yErr := decodeSegment(key.Y)
		if xErr != nil || yErr != nil {
			return nil, errors.New("oidc: invalid EC coordinates")
		}
		var curve elliptic.Curve
		switch key.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("oidc: unsupported EC curve %q", key.Crv)
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(x) > size || len(y) > size {
			return nil, errors.New("oidc: invalid EC coordinate length")
		}
		uncompressed := make([]byte, 1+2*size)
		uncompressed[0] = 0x04
		copy(uncompressed[1+size-len(x):1+size], x)
		copy(uncompressed[1+2*size-len(y):], y)
		parsed, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
		if err != nil {
			return nil, err
		}
		return parsed, nil
	case "OKP":
		if key.Crv != "Ed25519" {
			return nil, fmt.Errorf("oidc: unsupported OKP curve %q", key.Crv)
		}
		x, err := decodeSegment(key.X)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("oidc: unsupported key type %q", key.Kty)
	}
}

func (s *KeySet) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.uri, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: jwks status %d", resp.StatusCode)
	}
	var document jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&document); err != nil {
		return fmt.Errorf("oidc: decode jwks: %w", err)
	}
	keys := make(map[string]any)
	for _, key := range document.Keys {
		parsed, err := parseKey(key)
		if err != nil {
			continue
		}
		keys[key.Kid] = parsed
	}
	if len(keys) == 0 {
		return errors.New("oidc: jwks has no usable keys")
	}
	s.keys = keys
	s.fetched = time.Now()
	return nil
}

func (s *KeySet) key(ctx context.Context, kid string) (any, error) {
	s.mu <- struct{}{}
	defer func() { <-s.mu }()
	if time.Since(s.fetched) > keySetTTL {
		if err := s.refresh(ctx); err != nil {
			return nil, err
		}
	}
	key, ok := s.keys[kid]
	if !ok {
		if err := s.refresh(ctx); err != nil {
			return nil, err
		}
		key, ok = s.keys[kid]
	}
	if !ok {
		return nil, errors.New("oidc: unknown signing key")
	}
	return key, nil
}

// Claims are the verified identity assertions Signet consumes.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Nonce         string
}

func boolClaim(value any) bool {
	verified, ok := value.(bool)
	return ok && verified
}

func stringClaim(claims jwt.MapClaims, name string) string {
	value, _ := claims[name].(string)
	return value
}

func keyForMethod(method jwt.SigningMethod, key any) (any, error) {
	switch method.(type) {
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		if _, ok := key.(*rsa.PublicKey); !ok {
			return nil, errors.New("oidc: key type does not match signing method")
		}
	case *jwt.SigningMethodECDSA:
		if _, ok := key.(*ecdsa.PublicKey); !ok {
			return nil, errors.New("oidc: key type does not match signing method")
		}
	case *jwt.SigningMethodEd25519:
		if _, ok := key.(ed25519.PublicKey); !ok {
			return nil, errors.New("oidc: key type does not match signing method")
		}
	default:
		return nil, errors.New("oidc: unsupported signing method")
	}
	return key, nil
}

// Verify verifies an ID token against the key set, issuer, audience and
// allowed algorithms. A verification failure is always an error.
func Verify(ctx context.Context, set *KeySet, raw, issuer, audience string, algorithms []string) (*Claims, error) {
	parsed, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		allowed := false
		for _, candidate := range algorithms {
			if candidate == token.Method.Alg() {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, errors.New("oidc: signing algorithm not allowed")
		}
		kid, _ := token.Header["kid"].(string)
		key, err := set.key(ctx, kid)
		if err != nil {
			return nil, err
		}
		return keyForMethod(token.Method, key)
	}, jwt.WithValidMethods(algorithms), jwt.WithIssuer(issuer), jwt.WithAudience(audience),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(30*time.Second))
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("oidc: verify id token: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || stringClaim(claims, "sub") == "" {
		return nil, errors.New("oidc: id token missing subject")
	}
	return &Claims{
		Subject:       stringClaim(claims, "sub"),
		Email:         stringClaim(claims, "email"),
		EmailVerified: boolClaim(claims["email_verified"]),
		Nonce:         stringClaim(claims, "nonce"),
	}, nil
}
