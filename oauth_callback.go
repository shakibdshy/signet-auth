package signet

import (
	"context"

	"github.com/shakibdshy/signet/internal/core"
)

// OAuthCallbackInput carries the provider code and state.
type OAuthCallbackInput = core.OAuthCallbackInput

// OAuthCallbackResult carries a User or a one-time link token.
type OAuthCallbackResult = core.OAuthCallbackResult

// LinkOAuthAccountInput carries the link token and authenticated User ID.
type LinkOAuthAccountInput = core.LinkOAuthAccountInput

// OAuthCallback redeems the provider code.
func (c *Client) OAuthCallback(ctx context.Context, in OAuthCallbackInput) (*OAuthCallbackResult, error) {
	if c.cfg.OAuth == nil {
		return nil, ErrOAuthDisabled
	}
	return c.oauth.Callback(ctx, in)
}

// LinkOAuthAccount links a provider Account after explicit consent.
func (c *Client) LinkOAuthAccount(ctx context.Context, in LinkOAuthAccountInput) error {
	if c.cfg.OAuth == nil {
		return ErrOAuthDisabled
	}
	return c.oauth.LinkAccount(ctx, in)
}
