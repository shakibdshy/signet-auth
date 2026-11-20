package signet

import (
	"context"

	"github.com/shakibdshy/signet/internal/core"
)

// SendVerificationInput requests a verification email for an email address.
type SendVerificationInput = core.SendVerificationInput

// VerifyEmailInput carries a verification Token.
type VerifyEmailInput = core.VerifyEmailInput

// SendVerification sends a verification email. It succeeds for unknown emails
// so callers cannot enumerate registered Users.
func (c *Client) SendVerification(ctx context.Context, in SendVerificationInput) error {
	return c.verification.SendVerification(ctx, in)
}

// VerifyEmail consumes a verification Token and marks its User verified.
func (c *Client) VerifyEmail(ctx context.Context, in VerifyEmailInput) error {
	return c.verification.VerifyEmail(ctx, in)
}
