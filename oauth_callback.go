package signet

import (
	"context"
	"errors"
	"strings"

	"github.com/shakibdshy/signet/internal/core"
)

// OAuthCallbackInput carries the provider's code and the encrypted state.
type OAuthCallbackInput = core.OAuthCallbackInput

// OAuthCallbackResult carries either a signed-in User with a Session token or
// a one-time token for explicit linking.
type OAuthCallbackResult = core.OAuthCallbackResult

// LinkOAuthAccountInput carries the one-time link token and the authenticated
// User who is linking the provider Account.
type LinkOAuthAccountInput = core.LinkOAuthAccountInput

// OAuthCallback completes the Authorization Code flow.
func (c *Client) OAuthCallback(ctx context.Context, in OAuthCallbackInput) (*OAuthCallbackResult, error) {
	if c.cfg.OAuth == nil {
		return nil, ErrOAuthDisabled
	}
	if err := c.allow(ctx, "oauth_callback", in.RateLimitKey); err != nil {
		return nil, err
	}
	// State is single-use: consuming it here rejects replayed callbacks.
	if _, err := c.consumeToken(ctx, TokenOAuthState, in.State); err != nil {
		if errors.Is(err, ErrTokenInvalid) || errors.Is(err, ErrTokenExpired) {
			return nil, ErrOAuthInvalidState
		}
		return nil, err
	}
	state, err := c.openState(in.State)
	if err != nil {
		return nil, err
	}
	provider := c.oauthProvider(state.Provider)
	if provider == nil {
		return nil, ErrOAuthProviderNotFound
	}
	if !c.redirectAllowed(state.Redirect) {
		return nil, ErrOAuthRedirectNotAllowed
	}
	redirectURI := strings.TrimRight(c.cfg.OAuth.RedirectBaseURL, "/") + "/oauth/callback"
	identity, err := provider.Exchange(ctx, in.Code, state.Verifier, redirectURI)
	if err != nil {
		return nil, err
	}

	if !identity.EmailVerified {
		return c.pendingOAuthLink(ctx, identity, state.Redirect)
	}
	user, err := c.linkOrCreateUser(ctx, identity)
	if err != nil {
		return nil, err
	}
	sessionToken, err := c.createSession(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	c.logInfo("oauth_sign_in", "user_id", user.ID, "provider", identity.Provider)
	c.cfg.OnSignIn(ctx, redactedUser(user))
	return &OAuthCallbackResult{User: user, SessionToken: sessionToken, Redirect: state.Redirect}, nil
}

// LinkOAuthAccount links a provider Account after explicit user consent.
func (c *Client) LinkOAuthAccount(ctx context.Context, in LinkOAuthAccountInput) error {
	if c.cfg.OAuth == nil {
		return ErrOAuthDisabled
	}
	payload, err := c.openLink(in.LinkToken)
	if err != nil {
		return err
	}
	if _, err := c.consumeToken(ctx, TokenOAuthLink, in.LinkToken); err != nil {
		return err
	}
	user, err := c.cfg.Store.UserByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	if err := c.linkAccount(ctx, user, &payload.Identity); err != nil {
		return err
	}
	c.logInfo("oauth_link", "user_id", user.ID, "provider", payload.Identity.Provider)
	return nil
}

func (c *Client) pendingOAuthLink(ctx context.Context, identity *OAuthIdentity, redirect string) (*OAuthCallbackResult, error) {
	linkToken, err := c.sealLink(*identity)
	if err != nil {
		return nil, err
	}
	token := &Token{
		ID:        newID(),
		Kind:      TokenOAuthLink,
		Hash:      digestSecret(linkToken),
		ExpiresAt: c.cfg.Clock.Now().Add(oauthLinkTTL),
		CreatedAt: c.cfg.Clock.Now(),
	}
	if err := c.cfg.Store.CreateToken(ctx, token); err != nil {
		return nil, err
	}
	c.logInfo("oauth_link_required", "provider", identity.Provider)
	return &OAuthCallbackResult{LinkToken: linkToken, Redirect: redirect}, nil
}

func (c *Client) linkOrCreateUser(ctx context.Context, identity *OAuthIdentity) (*User, error) {
	email := normalizeEmail(identity.Email)
	if email == "" {
		return nil, ErrOAuthEmailNotVerified
	}
	user, err := c.cfg.Store.UserByEmail(ctx, email)
	if err == nil {
		if err := c.linkAccount(ctx, user, identity); err != nil {
			return nil, err
		}
		return user, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := c.cfg.Clock.Now()
	user = &User{ID: newID(), Email: email, EmailVerified: true, CreatedAt: now, UpdatedAt: now}
	if err := c.cfg.Store.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	if err := c.linkAccount(ctx, user, identity); err != nil {
		_ = c.cfg.Store.DeleteUser(ctx, user.ID)
		return nil, err
	}
	c.logInfo("oauth_user_created", "user_id", user.ID)
	return user, nil
}

func (c *Client) linkAccount(ctx context.Context, user *User, identity *OAuthIdentity) error {
	existing, err := c.cfg.Store.AccountByProvider(ctx, identity.Provider, identity.ProviderUserID)
	if err == nil {
		if existing.UserID != user.ID {
			return ErrOAuthAccountConflict
		}
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	account := &Account{
		ID:             newID(),
		UserID:         user.ID,
		Provider:       identity.Provider,
		ProviderUserID: identity.ProviderUserID,
		Email:          normalizeEmail(identity.Email),
		EmailVerified:  identity.EmailVerified,
		CreatedAt:      c.cfg.Clock.Now(),
	}
	return c.cfg.Store.CreateAccount(ctx, account)
}
