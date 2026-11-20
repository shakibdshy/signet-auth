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
	result, err := c.oauth.Callback(ctx, in)
	if err != nil {
		return nil, err
	}
	// Application hooks are a root concern. Fire the same redacted sign-in
	// event as the password flow, but only once a User actually signed in —
	// a pending link token is not a completed sign-in.
	if result.User != nil {
		c.cfg.OnSignIn(ctx, redactedUser(result.User))
	}
	return result, nil
}

// LinkOAuthAccount links a provider Account after explicit consent.
func (c *Client) LinkOAuthAccount(ctx context.Context, in LinkOAuthAccountInput) error {
	if c.cfg.OAuth == nil {
		return ErrOAuthDisabled
	}
	return c.oauth.LinkAccount(ctx, in)
}
