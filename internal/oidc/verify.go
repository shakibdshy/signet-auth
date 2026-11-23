package oidc

import (
	"context"
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
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

// KeySet caches the public keys published by a Provider.
type KeySet struct {
	client  *http.Client
	uri     string
	mu      chan struct{}
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

// NewKeySet returns a cache for the given JWKS URI.
func NewKeySet(client *http.Client, uri string) *KeySet {
	return &KeySet{client: client, uri: uri, mu: make(chan struct{}, 1), keys: make(map[string]*rsa.PublicKey)}
}

func decodeSegment(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
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
	keys := make(map[string]*rsa.PublicKey)
	for _, key := range document.Keys {
		if key.Kty != "RSA" {
			continue
		}
		n, nErr := decodeSegment(key.N)
		e, eErr := decodeSegment(key.E)
		if nErr != nil || eErr != nil || len(e) == 0 {
			continue
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 + int(b)
		}
		keys[key.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
	}
	if len(keys) == 0 {
		return errors.New("oidc: jwks has no usable RSA keys")
	}
	s.keys = keys
	s.fetched = time.Now()
	return nil
}

func (s *KeySet) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	s.mu <- struct{}{}
	defer func() { <-s.mu }()
	if time.Since(s.fetched) > keySetTTL {
		if err := s.refresh(ctx); err != nil {
			return nil, err
		}
	}
	key, ok := s.keys[kid]
	if !ok {
		// A key may have rotated; refresh once before giving up.
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
	Name          string
	Nonce         string
}

func boolClaim(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return typed == "true"
	}
	return false
}

func stringClaim(claims jwt.MapClaims, name string) string {
	value, _ := claims[name].(string)
	return value
}

// Verify verifies an ID token against the key set, issuer, audience and
// allowed algorithms. A verification failure is always an error.
func Verify(ctx context.Context, set *KeySet, raw, issuer, audience string, algorithms []string) (*Claims, error) {
	parsed, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		alg, ok := token.Method.(*jwt.SigningMethodRSA)
		if !ok {
			return nil, errors.New("oidc: unsupported signing method")
		}
		allowed := false
		for _, candidate := range algorithms {
			if candidate == alg.Alg() {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, errors.New("oidc: signing algorithm not allowed")
		}
		kid, _ := token.Header["kid"].(string)
		return set.key(ctx, kid)
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
		Name:          stringClaim(claims, "name"),
		Nonce:         stringClaim(claims, "nonce"),
	}, nil
}
