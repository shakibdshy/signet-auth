// Package audit projects Signet's security events to an application-owned sink.
package audit

import (
	"context"
	"log/slog"

	"github.com/shakibdshy/signet/internal/core"
)

// Event names reuse the strings already emitted through the application logger.
const (
	SignUp              = "sign_up"
	SignInSuccess       = "sign_in_success"
	SignInFailure       = "sign_in_failure"
	SignOut             = "sign_out"
	PasswordChanged     = "password_changed"
	ResetPassword       = "reset-password"
	EmailVerified       = "email_verified"
	EmailChanged        = "email_changed"
	UserDeleted         = "user_deleted"
	AccountUnlinked     = "account_unlinked"
	TwoFactorEnabled    = "two_factor_enabled"
	TwoFactorDisabled   = "two_factor_disabled"
	BackupCodeUsed      = "backup_code_used"
	RefreshReuse        = "refresh_token_reuse"
	OAuthSignIn         = "oauth_sign_in"
	MagicLinkSignIn     = "magic_link_sign_in"
	EmailOTPSignIn      = "email_otp_sign_in"
	AuthorizationDenied = "authorization_denied"
	APIKeyCreated       = "api_key_created"
	APIKeyRevoked       = "api_key_revoked"
)

// Emit records an event when a sink is configured. A sink failure is logged
// and never changes the request outcome.
func Emit(ctx context.Context, sink core.AuditSink, logger *slog.Logger, event core.AuditEvent) {
	if sink == nil {
		return
	}
	if err := sink.Record(ctx, event); err != nil && logger != nil {
		logger.Warn("audit_sink_failed", "event", event.Name, "error", err)
	}
}
