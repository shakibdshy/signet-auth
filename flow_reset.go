package signet

import (
	"context"
	"errors"
	"time"
)

const resetTokenTTL = time.Hour

// SendPasswordResetInput requests a password reset email.
type SendPasswordResetInput struct {
	Email        string `json:"email"`
	RateLimitKey string `json:"-"`
}

// ResetPasswordInput carries a reset Token and the replacement password.
type ResetPasswordInput struct {
	Token        string `json:"token"`
	NewPassword  string `json:"new_password"`
	RateLimitKey string `json:"-"`
}

// SendPasswordReset sends a reset email. It succeeds for unknown emails so
// callers cannot enumerate registered Users.
func (c *Client) SendPasswordReset(ctx context.Context, in SendPasswordResetInput) error {
	email := normalizeEmail(in.Email)
	if email == "" {
		return ErrInvalidEmail
	}
	if err := c.allow(ctx, "password_reset_send", in.RateLimitKey); err != nil {
		return err
	}
	user, err := c.cfg.Store.UserByEmail(ctx, email)
	if errors.Is(err, ErrNotFound) {
		// Equalize work with the registered-email path without sending mail.
		// Mail transport time itself remains a signal; eliminating that needs
		// queued delivery, which is outside this phase.
		raw, _ := newRawSecret()
		_ = digestSecret(raw)
		_ = c.cfg.Templates.ResetPassword(TemplateData{Email: email, ExpiresAt: c.cfg.Clock.Now().Add(resetTokenTTL)})
		return nil
	}
	if err != nil {
		return err
	}
	if err := c.cfg.Store.DeleteTokensForUser(ctx, user.ID, TokenResetPassword); err != nil {
		return err
	}
	raw, token, err := c.issueOneTimeToken(ctx, user.ID, TokenResetPassword, resetTokenTTL)
	if err != nil {
		return err
	}
	message := c.cfg.Templates.ResetPassword(TemplateData{
		Email: user.Email, Name: user.Name,
		URL: c.emailLink("/reset", raw), ExpiresAt: token.ExpiresAt,
	})
	if err := c.cfg.Mailer.Send(ctx, message); err != nil {
		c.logWarn("password_reset_email_failed", "user_id", user.ID, "error", err)
		return err
	}
	c.logInfo("password_reset_sent", "user_id", user.ID)
	return nil
}

// ResetPassword consumes a reset Token and replaces the credential verifier.
func (c *Client) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	if in.Token == "" {
		return ErrTokenInvalid
	}
	if len(in.NewPassword) < c.cfg.Password.MinLength {
		return ErrPasswordTooShort
	}
	if len(in.NewPassword) > c.cfg.Password.MaxLength {
		return ErrPasswordTooLong
	}
	if err := c.allow(ctx, "password_reset", in.RateLimitKey); err != nil {
		return err
	}
	token, err := c.consumeToken(ctx, TokenResetPassword, in.Token)
	if err != nil {
		return err
	}
	user, err := c.cfg.Store.UserByID(ctx, token.UserID)
	if err != nil {
		return err
	}
	account, err := c.cfg.Store.AccountByProvider(ctx, credentialProvider, user.ID)
	if err != nil {
		return err
	}
	// OWASP Forgot Password Cheat Sheet: a successful reset must invalidate
	// every outstanding reset Token and every Session, so a stolen link or a
	// Session established before the reset cannot grant access afterwards.
	// Revocation runs before the verifier changes and its errors are returned:
	// reporting success while credentials remain live would be worse than
	// retrying the reset.
	if err := c.cfg.Store.DeleteTokensForUser(ctx, user.ID, TokenResetPassword); err != nil {
		return err
	}
	if err := c.cfg.Store.DeleteSessionsForUser(ctx, user.ID); err != nil {
		return err
	}
	encoded, err := c.cfg.PasswordHasher.Hash(ctx, in.NewPassword)
	if err != nil {
		return err
	}
	updated := *account
	updated.PasswordHash = encoded
	if err := c.cfg.Store.UpdateAccount(ctx, &updated); err != nil {
		return err
	}
	c.logInfo("password_reset", "user_id", user.ID)

	message := c.cfg.Templates.PasswordChanged(TemplateData{Email: user.Email, Name: user.Name})
	if err := c.cfg.Mailer.Send(ctx, message); err != nil {
		c.logWarn("password_changed_notification_failed", "user_id", user.ID, "error", err)
	}
	return nil
}
