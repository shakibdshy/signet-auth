package signet

import (
	"context"

	"github.com/shakibdshy/signet/internal/core"
)

// JWTConfig enables optional bearer-token mode. A nil Config.JWT keeps cookie
// sessions only.
type JWTConfig = core.JWTConfig

// TokenInput selects an exchange: supply email and password, or a Refresh token.
type TokenInput = core.TokenInput

// TokenPair is the result of a token exchange or refresh.
type TokenPair = core.TokenPair

// ExchangeToken issues a TokenPair for credentials, or rotates a Refresh token.
func (c *Client) ExchangeToken(ctx context.Context, in TokenInput) (*TokenPair, error) {
	if c.jwtService == nil {
		return nil, ErrJWTDisabled
	}
	return c.jwtService.Exchange(ctx, in)
}

// VerifyAccessToken validates a bearer token and returns its User.
func (c *Client) VerifyAccessToken(ctx context.Context, raw string) (*User, error) {
	if c.jwtService == nil {
		return nil, ErrJWTDisabled
	}
	return c.jwtService.VerifyAccessToken(ctx, raw)
}
