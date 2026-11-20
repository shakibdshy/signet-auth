package signet

import "github.com/shakibdshy/signet/internal/core"

var (
	// ErrNotFound reports that a User, Account, Session or Token does not exist.
	ErrNotFound = core.ErrNotFound
	// ErrInvalidCredentials reports a failed sign-in attempt.
	ErrInvalidCredentials = core.ErrInvalidCredentials
	// ErrEmailNotVerified reports a sign-in blocked by an unverified email.
	ErrEmailNotVerified = core.ErrEmailNotVerified
	// ErrRateLimited reports that an action exceeded its rate limit.
	ErrRateLimited = core.ErrRateLimited
	// ErrTokenExpired reports a Token past its expiry.
	ErrTokenExpired = core.ErrTokenExpired
	// ErrTokenInvalid reports a malformed, unknown or already-used Token.
	ErrTokenInvalid = core.ErrTokenInvalid
	// ErrMissingStore reports that Config.Store was not supplied.
	ErrMissingStore = core.ErrMissingStore
	// ErrMissingMailer reports that Config.Mailer was not supplied.
	ErrMissingMailer = core.ErrMissingMailer
	// ErrMissingHasher reports that Config.PasswordHasher was not supplied.
	ErrMissingHasher = core.ErrMissingHasher
	// ErrMissingRateLimiter reports that Config.RateLimiter was not supplied.
	ErrMissingRateLimiter = core.ErrMissingRateLimiter
	// ErrInsecureConfig reports a configuration that would weaken cookie
	// security without the explicit opt-in.
	ErrInsecureConfig = core.ErrInsecureConfig
	// ErrInvalidEmail reports a missing or malformed email address.
	ErrInvalidEmail = core.ErrInvalidEmail
	// ErrPasswordTooShort reports a password below the configured minimum.
	ErrPasswordTooShort = core.ErrPasswordTooShort
	// ErrPasswordTooLong reports a password above the configured maximum.
	ErrPasswordTooLong = core.ErrPasswordTooLong
	// ErrEmailAlreadyExists reports a sign-up for a registered email.
	ErrEmailAlreadyExists = core.ErrEmailAlreadyExists
	// ErrJWTDisabled reports token use while JWT mode is not configured.
	ErrJWTDisabled = core.ErrJWTDisabled
	// ErrInvalidJWTAlgorithm reports an algorithm outside the allowlist.
	ErrInvalidJWTAlgorithm = core.ErrInvalidJWTAlgorithm
	// ErrInvalidJWTKey reports a signing key that does not match the algorithm.
	ErrInvalidJWTKey = core.ErrInvalidJWTKey
	// ErrRefreshReuse reports replay of a consumed Refresh token.
	ErrRefreshReuse = core.ErrRefreshReuse
	// ErrInvalidOAuthConfig reports invalid OAuth configuration.
	ErrInvalidOAuthConfig = core.ErrInvalidOAuthConfig
	// ErrOAuthDisabled reports OAuth use while Config.OAuth is nil.
	ErrOAuthDisabled = core.ErrOAuthDisabled
	// ErrOAuthProviderNotFound reports an unregistered provider name.
	ErrOAuthProviderNotFound = core.ErrOAuthProviderNotFound
	// ErrOAuthInvalidState reports tampered, expired or mismatched state.
	ErrOAuthInvalidState = core.ErrOAuthInvalidState
	// ErrOAuthRedirectNotAllowed reports a redirect outside the allowlist.
	ErrOAuthRedirectNotAllowed = core.ErrOAuthRedirectNotAllowed
	// ErrOAuthEmailNotVerified reports an OAuth identity without a usable verified email.
	ErrOAuthEmailNotVerified = core.ErrOAuthEmailNotVerified
	// ErrOAuthAccountConflict reports a provider Account owned by another User.
	ErrOAuthAccountConflict = core.ErrOAuthAccountConflict
	// ErrInvalidCSRFConfig reports a missing or short CSRF signing key.
	ErrInvalidCSRFConfig = core.ErrInvalidCSRFConfig
)
