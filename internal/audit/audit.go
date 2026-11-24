// Package audit projects Signet's security events to an application-owned sink.
package audit

import (
	"context"
	"log/slog"

	"github.com/shakibdshy/signet/internal/core"
)

// Event names reuse the strings already emitted through the application logger.
const (
	SignUp                    = "sign_up"
	SignInSuccess             = "sign_in_success"
	SignInFailure             = "sign_in_failure"
	SignOut                   = "sign_out"
	PasswordChanged           = "password_changed"
	ResetPassword             = "reset-password"
	EmailVerified             = "email_verified"
	EmailChanged              = "email_changed"
	UserDeleted               = "user_deleted"
	AccountUnlinked           = "account_unlinked"
	TwoFactorEnabled          = "two_factor_enabled"
	TwoFactorDisabled         = "two_factor_disabled"
	BackupCodeUsed            = "backup_code_used"
	RefreshReuse              = "refresh_token_reuse"
	OAuthSignIn               = "oauth_sign_in"
	MagicLinkSignIn           = "magic_link_sign_in"
	EmailOTPSignIn            = "email_otp_sign_in"
	AuthorizationDenied       = "authorization_denied"
	APIKeyCreated             = "api_key_created"
	APIKeyRevoked             = "api_key_revoked"
	OrganizationCreated       = "organization_created"
	OrganizationMemberAdded   = "organization_member_added"
	OrganizationMemberRemoved = "organization_member_removed"
	OrganizationMemberRoleSet = "organization_member_role_set"
	UserBanned                = "user_banned"
	UserUnbanned              = "user_unbanned"
	UserRolesSet              = "user_roles_set"
	UserSessionRevoked        = "user_session_revoked"
	UserImpersonated          = "user_impersonated"
	ImpersonationStopped      = "impersonation_stopped"
	PasskeyRegistrationFailed = "passkey_registration_failed"
	PasskeyEnrolled           = "passkey_enrolled"
	PasskeyAssertionFailed    = "passkey_assertion_failed"
	//nolint:gosec // G101: event name, not a credential.
	PasskeySignCountRegression = "passkey_sign_count_regression"
	PasskeySignIn              = "passkey_sign_in"
	PasskeyDeleted             = "passkey_deleted"
	OAuthConsentDenied         = "oauth_consent_denied"
	OAuthCodeIssued            = "oauth_code_issued"
	//nolint:gosec // G101: event name, not a credential.
	OAuthTokenIssued     = "oauth_token_issued"
	OAuthDeviceApproved  = "oauth_device_approved"
	SSODomainUnverified  = "sso_domain_unverified"
	SSOConnectionCreated = "sso_connection_created"
	SSOConnectionDeleted = "sso_connection_deleted"
	SSOSignIn            = "sso_sign_in"
	SCIMUnauthorized     = "scim_unauthorized"
	SCIMUserCreated      = "scim_user_created"
	SCIMUserUpdated      = "scim_user_updated"
	SCIMUserDeleted      = "scim_user_deleted"
	SCIMGroupCreated     = "scim_group_created"
	SCIMGroupUpdated     = "scim_group_updated"
	SCIMGroupDeleted     = "scim_group_deleted"
	UserUpdated          = "user_updated"
	PasswordSet          = "password_set"
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
