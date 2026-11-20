package signet

import (
	"context"

	"github.com/shakibdshy/signet/internal/core"
)

// OAuthStartInput selects a provider and redirect target.
type OAuthStartInput = core.OAuthStartInput

// OAuthStartResult carries the provider authorization URL.
type OAuthStartResult = core.OAuthStartResult

// OAuthStart begins an Authorization Code flow with PKCE.
func (c *Client) OAuthStart(ctx context.Context, in OAuthStartInput) (*OAuthStartResult, error) {
	if c.cfg.OAuth == nil {
		return nil, ErrOAuthDisabled
	}
	return c.oauth.Start(ctx, in)
}
