package signet

import (
	"context"

	"github.com/shakibdshy/signet/internal/core"
)

// SendPasswordResetInput requests a password reset email.
type SendPasswordResetInput = core.SendPasswordResetInput

// ResetPasswordInput carries a reset Token and the replacement password.
type ResetPasswordInput = core.ResetPasswordInput

// SendPasswordReset sends a reset email. It succeeds for unknown emails so
// callers cannot enumerate registered Users.
func (c *Client) SendPasswordReset(ctx context.Context, in SendPasswordResetInput) error {
	return c.verification.SendPasswordReset(ctx, in)
}

// ResetPassword consumes a reset Token and replaces the credential verifier.
func (c *Client) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	return c.verification.ResetPassword(ctx, in)
}
