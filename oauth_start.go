package signet

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// OAuthStartInput selects a provider and the approved redirect target.
type OAuthStartInput struct {
	Provider     string `json:"provider"`
	Redirect     string `json:"redirect"`
	RateLimitKey string `json:"-"`
}

// OAuthStartResult carries the provider authorization URL.
type OAuthStartResult struct {
	URL string `json:"url"`
}

// OAuthStart begins an Authorization Code flow with PKCE and encrypted state.
func (c *Client) OAuthStart(ctx context.Context, in OAuthStartInput) (*OAuthStartResult, error) {
	if c.cfg.OAuth == nil {
		return nil, ErrOAuthDisabled
	}
	if err := c.allow(ctx, "oauth_start", in.RateLimitKey); err != nil {
		return nil, err
	}
	if !c.redirectAllowed(in.Redirect) {
		return nil, ErrOAuthRedirectNotAllowed
	}
	provider := c.oauthProvider(in.Provider)
	if provider == nil {
		return nil, ErrOAuthProviderNotFound
	}
	verifier, _ := newRawSecret()
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	nonce, _ := newRawSecret()
	state, err := c.sealState(oauthState{
		Provider:  in.Provider,
		Redirect:  in.Redirect,
		Verifier:  verifier,
		Nonce:     nonce,
		ExpiresAt: c.cfg.Clock.Now().Add(oauthStateTTL),
	})
	if err != nil {
		return nil, err
	}
	now := c.cfg.Clock.Now()
	if err := c.cfg.Store.CreateToken(ctx, &Token{
		ID:        newID(),
		Kind:      TokenOAuthState,
		Hash:      digestSecret(state),
		ExpiresAt: now.Add(oauthStateTTL),
		CreatedAt: now,
	}); err != nil {
		return nil, err
	}
	redirectURI := strings.TrimRight(c.cfg.OAuth.RedirectBaseURL, "/") + "/oauth/callback"
	url := provider.AuthURL("", redirectURI, state, challenge)
	c.logInfo("oauth_start", "provider", in.Provider)
	return &OAuthStartResult{URL: url}, nil
}
