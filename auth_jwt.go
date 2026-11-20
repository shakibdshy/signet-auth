package signet

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shakibdshy/signet/internal/core"
)

// JWTConfig enables optional bearer-token mode. A nil Config.JWT keeps cookie
// sessions only.
type JWTConfig = core.JWTConfig

// TokenInput selects an exchange: supply email and password, or a Refresh token.
type TokenInput = core.TokenInput

// TokenPair is the result of a token exchange or refresh.
type TokenPair = core.TokenPair

const (
	defaultAccessTTL  = 15 * time.Minute
	defaultRefreshTTL = 30 * 24 * time.Hour
)

type jwtAlgorithm struct {
	method   jwt.SigningMethod
	validKey func(any) bool
}

var jwtAlgorithms = map[string]jwtAlgorithm{
	"HS256": {jwt.SigningMethodHS256, func(key any) bool { _, ok := key.([]byte); return ok }},
	"RS256": {jwt.SigningMethodRS256, func(key any) bool { _, ok := key.(*rsa.PrivateKey); return ok }},
	"EdDSA": {jwt.SigningMethodEdDSA, func(key any) bool { _, ok := key.(ed25519.PrivateKey); return ok }},
}

func validateJWTConfig(cfg *JWTConfig) error {
	algorithm, ok := jwtAlgorithms[cfg.Algorithm]
	if !ok {
		return ErrInvalidJWTAlgorithm
	}
	if !algorithm.validKey(cfg.Key) {
		return ErrInvalidJWTKey
	}
	if cfg.AccessTTL == 0 {
		cfg.AccessTTL = defaultAccessTTL
	}
	if cfg.RefreshTTL == 0 {
		cfg.RefreshTTL = defaultRefreshTTL
	}
	return nil
}

// ExchangeToken issues a TokenPair for credentials, or rotates a Refresh token.
func (c *Client) ExchangeToken(ctx context.Context, in TokenInput) (*TokenPair, error) {
	if c.jwt == nil {
		return nil, ErrJWTDisabled
	}
	if in.RefreshToken != "" {
		if err := c.allow(ctx, "token", in.RateLimitKey); err != nil {
			return nil, err
		}
		return c.refreshTokens(ctx, in.RefreshToken)
	}
	result, err := c.SignIn(ctx, SignInInput{
		Email: in.Email, Password: in.Password, RateLimitKey: in.RateLimitKey,
	})
	if err != nil {
		return nil, err
	}
	return c.issueTokens(ctx, result.User.ID)
}

// VerifyAccessToken validates a bearer token and returns its User.
func (c *Client) VerifyAccessToken(ctx context.Context, raw string) (*User, error) {
	if c.jwt == nil {
		return nil, ErrJWTDisabled
	}
	claims := &jwt.RegisteredClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != c.jwt.Algorithm {
			return nil, ErrInvalidJWTAlgorithm
		}
		return c.jwt.Key, nil
	}, jwt.WithValidMethods([]string{c.jwt.Algorithm}))
	if err != nil || !parsed.Valid {
		return nil, ErrTokenInvalid
	}
	if c.jwt.Issuer != "" && claims.Issuer != c.jwt.Issuer {
		return nil, ErrTokenInvalid
	}
	return c.cfg.Store.UserByID(ctx, claims.Subject)
}

func (c *Client) issueTokens(ctx context.Context, userID string) (*TokenPair, error) {
	now := c.cfg.Clock.Now()
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		Issuer:    c.jwt.Issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(c.jwt.AccessTTL)),
	}
	algorithm, ok := jwtAlgorithms[c.jwt.Algorithm]
	if !ok {
		return nil, ErrInvalidJWTAlgorithm
	}
	access, err := jwt.NewWithClaims(algorithm.method, claims).SignedString(c.jwt.Key)
	if err != nil {
		return nil, err
	}
	raw, digest := newRawSecret()
	token := &Token{
		ID:        newID(),
		UserID:    userID,
		Kind:      TokenRefresh,
		Hash:      digest,
		ExpiresAt: now.Add(c.jwt.RefreshTTL),
		CreatedAt: now,
	}
	if err := c.cfg.Store.CreateToken(ctx, token); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		RefreshToken: raw,
		ExpiresIn:    int64(c.jwt.AccessTTL / time.Second),
	}, nil
}

func (c *Client) refreshTokens(ctx context.Context, presented string) (*TokenPair, error) {
	digest := digestSecret(presented)
	token, err := c.cfg.Store.TokenByHash(ctx, TokenRefresh, digest)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	if token.UsedAt != nil {
		return c.handleRefreshReuse(ctx, token.UserID)
	}
	if !c.cfg.Clock.Now().Before(token.ExpiresAt) {
		return nil, ErrTokenExpired
	}
	consumed, err := c.cfg.Store.ConsumeToken(ctx, TokenRefresh, digest)
	if errors.Is(err, ErrNotFound) {
		return c.handleRefreshReuse(ctx, token.UserID)
	}
	if err != nil {
		return nil, err
	}
	user, err := c.cfg.Store.UserByID(ctx, consumed.UserID)
	if err != nil {
		return nil, err
	}
	if user.Disabled {
		return nil, ErrInvalidCredentials
	}
	return c.issueTokens(ctx, user.ID)
}

func (c *Client) handleRefreshReuse(ctx context.Context, userID string) (*TokenPair, error) {
	// Security: a replayed Refresh token is treated as theft. Contain it by
	// revoking every Session and Refresh token of that User.
	_ = c.cfg.Store.DeleteSessionsForUser(ctx, userID)
	for _, kind := range []TokenKind{TokenRefresh, TokenVerifyEmail, TokenResetPassword, TokenOAuthLink} {
		_ = c.cfg.Store.DeleteTokensForUser(ctx, userID, kind)
	}
	c.logWarn("refresh_token_reuse", "user_id", userID)
	return nil, ErrRefreshReuse
}
