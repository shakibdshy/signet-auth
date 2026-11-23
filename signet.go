package signet

import (
	"time"

	"github.com/shakibdshy/signet/internal/auth"
	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/mail"
)

// RateLimitRule overrides the limiter and key prefix for one endpoint.
type RateLimitRule = core.RateLimitRule

// Version is the current Signet version. It remains a development placeholder
// until the first release is tagged.
const Version = "0.0.0-dev"

// Clock supplies the current time so time-dependent behaviour can be tested
// without waiting.
type Clock = core.Clock

// SystemClock is the production Clock, backed by time.Now.
type SystemClock struct{}

// Now returns the current local time.
func (SystemClock) Now() time.Time { return time.Now() }

// Message is the email Signet asks a Mailer to deliver.
type Message = core.Message

// Mailer delivers transactional email such as verification and password
// reset messages.
type Mailer = core.Mailer

// RateLimiter decides whether an action identified by a key may proceed.
type RateLimiter = core.RateLimiter

// Store is the complete persistence contract Signet requires. It composes the
// four narrow contracts so an adapter can be written and tested one concern
// at a time. Lookup misses return ErrNotFound.
type Store = core.Store

// UserStore persists Users.
type UserStore = core.UserStore

// AccountStore persists Accounts.
type AccountStore = core.AccountStore

// SessionStore persists Sessions.
type SessionStore = core.SessionStore

// TokenStore persists Tokens.
type TokenStore = core.TokenStore

// User is the person whose identity Signet manages. A User is the stable
// subject that Accounts and Sessions belong to.
type User = core.User

// Account is a named way a User authenticates: either a credential or a link
// to an external identity provider. A User has one credential Account and may
// have several provider Accounts.
type Account = core.Account

// SystemOwnerID scopes API keys with no owning User.
const SystemOwnerID = core.SystemOwnerID

// Permission is an exact resource:action authorization string.
type Permission = core.Permission

// Published permission strings used by guarded operations.
const (
	PermissionUsersBan         = core.PermissionUsersBan
	PermissionUsersSetRole     = core.PermissionUsersSetRole
	PermissionUsersImpersonate = core.PermissionUsersImpersonate
	PermissionSessionsRevoke   = core.PermissionSessionsRevoke
	PermissionAPIKeysCreate    = core.PermissionAPIKeysCreate
	PermissionAPIKeysRevoke    = core.PermissionAPIKeysRevoke
	PermissionOrgsCreate       = core.PermissionOrgsCreate
	PermissionOrgsMemberAdd    = core.PermissionOrgsMemberAdd
	PermissionOrgsMemberRemove = core.PermissionOrgsMemberRemove
	PermissionOrgsMemberRole   = core.PermissionOrgsMemberRole
)

// TokenKind identifies the sensitive flow a Token proves.
type TokenKind = core.TokenKind

const (
	// TokenVerifyEmail proves a request to verify an email address.
	TokenVerifyEmail = core.TokenVerifyEmail
	// TokenDeleteUser proves a request to delete an Account.
	TokenDeleteUser = core.TokenDeleteUser
	// TokenChangeEmail proves a request to change a User's email address.
	TokenChangeEmail = core.TokenChangeEmail
	// TokenResetPassword proves a request to reset a password.
	TokenResetPassword = core.TokenResetPassword
	// TokenOAuthLink proves a request to link an external provider Account.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenOAuthLink = core.TokenOAuthLink
	// TokenRefresh is a rotating credential used to obtain a new Access token.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenRefresh = core.TokenRefresh
	// TokenOAuthState is an OAuth round trip's state, consumed on callback.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenOAuthState = core.TokenOAuthState
	// TokenMagicLink proves a passwordless magic-link sign-in.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenMagicLink = core.TokenMagicLink
	// TokenEmailOTP proves a passwordless six-digit email sign-in.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenEmailOTP = core.TokenEmailOTP
	// TokenTwoFactor proves a first factor awaiting a Second factor.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenTwoFactor = core.TokenTwoFactor
)

// Token is a single-use proof for one sensitive flow. Hash holds the stored
// form of the proof; the raw value is never persisted.
type Token = core.Token

// OAuthIdentity is the information a provider reports about a User.
type OAuthIdentity = core.OAuthIdentity

// OAuthProvider is the contract an external identity provider implements.
type OAuthProvider = core.OAuthProvider

// AuthURLWithNonce is implemented by Providers that bind an OIDC nonce.
type AuthURLWithNonce = core.AuthURLWithNonce

// ExchangeWithNonce is implemented by Providers that verify an OIDC nonce.
type ExchangeWithNonce = core.ExchangeWithNonce

// OAuthConfig enables external sign-in providers.
type OAuthConfig = core.OAuthConfig

// TemplateData is the information available to an email template.
type TemplateData = core.TemplateData

// EmailTemplates renders the transactional email Signet sends.
type EmailTemplates = core.EmailTemplates

// MagicLinkTemplates optionally renders the passwordless magic-link email.
type MagicLinkTemplates = core.MagicLinkTemplates

// EmailOTPTemplates optionally renders the passwordless OTP email.
type EmailOTPTemplates = core.EmailOTPTemplates

// DefaultTemplates is the built-in email template set.
var DefaultTemplates = mail.DefaultTemplates

// PasswordHasher stores and verifies password verifiers. The encoded value
// returned by Hash carries its algorithm and parameters so it can be upgraded.
type PasswordHasher = core.PasswordHasher

// Argon2idHasher stores password verifiers as Argon2id PHC strings. Its zero
// value uses the OWASP-recommended parameters.
type Argon2idHasher = auth.Argon2idHasher

// Session is one authenticated visit by a User.
type Session = core.Session

// APIKey is a digest-only credential for a non-human client.
type APIKey = core.APIKey

// Principal is the identity attached to a verified API key.
type Principal = core.Principal

// CreateAPIKeyInput describes a new API key.
type CreateAPIKeyInput = core.CreateAPIKeyInput

// CreateAPIKeyResult carries the raw key once and its stored record.
type CreateAPIKeyResult = core.CreateAPIKeyResult

// ListAPIKeysInput selects the keys owned by a User.
type ListAPIKeysInput = core.ListAPIKeysInput

// ListAPIKeysResult contains a User's API keys.
type ListAPIKeysResult = core.ListAPIKeysResult

// RevokeAPIKeyInput identifies a key to revoke.
type RevokeAPIKeyInput = core.RevokeAPIKeyInput

// AccountInfo is the safe representation of an Account.
type AccountInfo = core.AccountInfo

// ListAccountsInput selects the User whose Accounts should be listed.
type ListAccountsInput = core.ListAccountsInput

// ListAccountsResult contains the safe fields of a User's Accounts.
type ListAccountsResult = core.ListAccountsResult

// UnlinkAccountInput identifies one Account to unlink.
type UnlinkAccountInput = core.UnlinkAccountInput

// SessionInfo is the safe representation of a Session.
type SessionInfo = core.SessionInfo

// ListSessionsInput selects the User whose Sessions should be listed.
type ListSessionsInput = core.ListSessionsInput

// ListSessionsResult contains the safe fields of a User's Sessions.
type ListSessionsResult = core.ListSessionsResult

// RevokeSessionInput identifies one Session to revoke.
type RevokeSessionInput = core.RevokeSessionInput

// RevokeAllSessionsInput identifies the User whose Sessions should be revoked.
type RevokeAllSessionsInput = core.RevokeAllSessionsInput

// SignUpInput is the input to a sign-up.
type SignUpInput = core.SignUpInput

// SignUpResult is the outcome of a successful sign-up.
type SignUpResult = core.SignUpResult

// SignInInput is the input to a sign-in.
type SignInInput = core.SignInInput

// SignInResult is the outcome of a successful sign-in.
type SignInResult = core.SignInResult

// EnableTwoFactorInput enables Second factor enrollment.
type EnableTwoFactorInput = core.EnableTwoFactorInput

// EnableTwoFactorResult carries a provisioning URI and Backup codes.
type EnableTwoFactorResult = core.EnableTwoFactorResult

// VerifyTwoFactorInput exchanges a Two-factor challenge for a Session.
type VerifyTwoFactorInput = core.VerifyTwoFactorInput

// DisableTwoFactorInput removes a Second factor enrollment.
type DisableTwoFactorInput = core.DisableTwoFactorInput

// RegenerateBackupCodesInput replaces all Backup codes.
type RegenerateBackupCodesInput = core.RegenerateBackupCodesInput

// RegenerateBackupCodesResult carries fresh Backup codes.
type RegenerateBackupCodesResult = core.RegenerateBackupCodesResult

// SendMagicLinkInput requests a magic-link sign-in email.
type SendMagicLinkInput = core.SendMagicLinkInput

// VerifyMagicLinkInput carries a magic-link proof and, optionally, a callback URL.
type VerifyMagicLinkInput = core.VerifyMagicLinkInput

// SendEmailOTPInput requests a six-digit sign-in code by email.
type SendEmailOTPInput = core.SendEmailOTPInput

// VerifyEmailOTPInput carries a sign-in code and its email address.
type VerifyEmailOTPInput = core.VerifyEmailOTPInput

// SignOutInput is the input to a sign-out.
type SignOutInput = core.SignOutInput

// RequestDeleteUserInput identifies the User requesting account deletion.
type RequestDeleteUserInput = core.RequestDeleteUserInput

// ConfirmDeleteUserInput carries the proof from a deletion email.
type ConfirmDeleteUserInput = core.ConfirmDeleteUserInput

// ChangeEmailInput carries the new address and current password for an authenticated User.
type ChangeEmailInput = core.ChangeEmailInput

// VerifyEmailChangeInput carries the proof from an email-change message.
type VerifyEmailChangeInput = core.VerifyEmailChangeInput

// ChangePasswordInput carries the current and new password for an authenticated User.
type ChangePasswordInput = core.ChangePasswordInput

// SendVerificationInput requests a verification email for an email address.
type SendVerificationInput = core.SendVerificationInput

// VerifyEmailInput carries a verification Token.
type VerifyEmailInput = core.VerifyEmailInput

// SendPasswordResetInput requests a password reset email.
type SendPasswordResetInput = core.SendPasswordResetInput

// ResetPasswordInput carries a reset Token and the replacement password.
type ResetPasswordInput = core.ResetPasswordInput

// JWTConfig enables optional bearer-token mode. A nil Config.JWT keeps cookie
// sessions only.
type JWTConfig = core.JWTConfig

// TokenInput selects an exchange: supply email and password, or a Refresh token.
type TokenInput = core.TokenInput

// TokenPair is the result of a token exchange or refresh.
type TokenPair = core.TokenPair

// OAuthStartInput selects a provider and redirect target.
type OAuthStartInput = core.OAuthStartInput

// OAuthStartResult carries the provider authorization URL.
type OAuthStartResult = core.OAuthStartResult

// OAuthCallbackInput carries the provider code and state.
type OAuthCallbackInput = core.OAuthCallbackInput

// OAuthCallbackResult carries a User or a one-time link token.
type OAuthCallbackResult = core.OAuthCallbackResult

// LinkOAuthAccountInput carries the link token and authenticated User ID.
type LinkOAuthAccountInput = core.LinkOAuthAccountInput
