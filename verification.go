package signet

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"time"
)

const verificationTokenTTL = 24 * time.Hour

// SendVerificationInput requests a verification email for an email address.
type SendVerificationInput struct {
	Email        string `json:"email"`
	RateLimitKey string `json:"-"`
}

// VerifyEmailInput carries a verification Token.
type VerifyEmailInput struct {
	Token        string `json:"token"`
	RateLimitKey string `json:"-"`
}

// SendVerification sends a verification email. It succeeds for unknown emails
// so callers cannot enumerate registered Users.
func (c *Client) SendVerification(ctx context.Context, in SendVerificationInput) error {
	email := normalizeEmail(in.Email)
	if email == "" {
		return ErrInvalidEmail
	}
	if err := c.allow(ctx, "verification_send", in.RateLimitKey); err != nil {
		return err
	}
	user, err := c.cfg.Store.UserByEmail(ctx, email)
	if errors.Is(err, ErrNotFound) {
		// Equalize work with the registered-email path without sending mail.
		// Mail transport time itself remains a signal; eliminating that needs
		// queued delivery, which is outside this phase.
		raw, _ := newRawSecret()
		_ = digestSecret(raw)
		_ = c.cfg.Templates.VerifyEmail(TemplateData{Email: email, ExpiresAt: c.cfg.Clock.Now().Add(verificationTokenTTL)})
		return nil
	}
	if err != nil {
		return err
	}
	return c.sendVerification(ctx, user)
}

// VerifyEmail consumes a verification Token and marks its User verified.
func (c *Client) VerifyEmail(ctx context.Context, in VerifyEmailInput) error {
	if in.Token == "" {
		return ErrTokenInvalid
	}
	if err := c.allow(ctx, "verification", in.RateLimitKey); err != nil {
		return err
	}
	token, err := c.consumeToken(ctx, TokenVerifyEmail, in.Token)
	if err != nil {
		return err
	}
	user, err := c.cfg.Store.UserByID(ctx, token.UserID)
	if err != nil {
		return err
	}
	user.EmailVerified = true
	if err := c.cfg.Store.UpdateUser(ctx, user); err != nil {
		return err
	}
	c.logInfo("email_verified", "user_id", user.ID)
	return nil
}

func (c *Client) sendVerification(ctx context.Context, user *User) error {
	if err := c.cfg.Store.DeleteTokensForUser(ctx, user.ID, TokenVerifyEmail); err != nil {
		return err
	}
	raw, token, err := c.issueOneTimeToken(ctx, user.ID, TokenVerifyEmail, verificationTokenTTL)
	if err != nil {
		return err
	}
	message := c.cfg.Templates.VerifyEmail(TemplateData{
		Email: user.Email, Name: user.Name,
		URL: c.emailLink("/verify", raw), ExpiresAt: token.ExpiresAt,
	})
	if err := c.cfg.Mailer.Send(ctx, message); err != nil {
		c.logWarn("verification_email_failed", "user_id", user.ID, "error", err)
		return err
	}
	c.logInfo("verification_sent", "user_id", user.ID)
	return nil
}

func (c *Client) issueOneTimeToken(ctx context.Context, userID string, kind TokenKind, ttl time.Duration) (string, *Token, error) {
	raw, digest := newRawSecret()
	now := c.cfg.Clock.Now()
	token := &Token{
		ID:        newID(),
		UserID:    userID,
		Kind:      kind,
		Hash:      digest,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	if err := c.cfg.Store.CreateToken(ctx, token); err != nil {
		return "", nil, err
	}
	return raw, token, nil
}

func (c *Client) emailLink(path, raw string) string {
	return strings.TrimRight(c.cfg.AppURL, "/") + path + "?token=" + raw
}

func (c *Client) consumeToken(ctx context.Context, kind TokenKind, raw string) (*Token, error) {
	digest := digestSecret(raw)
	token, err := c.cfg.Store.TokenByHash(ctx, kind, digest)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	if token.UsedAt != nil {
		return nil, ErrTokenInvalid
	}
	if !c.cfg.Clock.Now().Before(token.ExpiresAt) {
		return nil, ErrTokenExpired
	}
	consumed, err := c.cfg.Store.ConsumeToken(ctx, kind, digest)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	// Compare in constant time even though the store already matched the digest.
	if subtle.ConstantTimeCompare([]byte(consumed.Hash), []byte(digest)) != 1 {
		return nil, ErrTokenInvalid
	}
	return consumed, nil
}
