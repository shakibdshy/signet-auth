package signet

import "github.com/shakibdshy/signet-auth/internal/core"

var (
	// ErrNotFound reports that a User, Account, Session or Token does not exist.
	ErrNotFound = core.ErrNotFound
	// ErrUserNotFound reports that no User exists for a supplied email.
	ErrUserNotFound = core.ErrUserNotFound
	// ErrInvalidMemberInput reports an ambiguous or missing Membership identifier.
	ErrInvalidMemberInput = core.ErrInvalidMemberInput
	// ErrMissingOrgID reports an organization endpoint called without organization_id.
	ErrMissingOrgID = core.ErrMissingOrgID
	// ErrInvalidCredentials reports a failed sign-in attempt.
	ErrInvalidCredentials = core.ErrInvalidCredentials
	// ErrEmailNotVerified reports a sign-in blocked by an unverified email.
	ErrEmailNotVerified = core.ErrEmailNotVerified
	// ErrRateLimited reports that an action exceeded its rate limit.
	ErrRateLimited = core.ErrRateLimited
	// ErrTokenExpired reports a Token past its expiry.
	ErrTokenExpired = core.ErrTokenExpired
	// ErrInvalidRateLimitRule reports a rule for an unknown endpoint name.
	ErrInvalidRateLimitRule = core.ErrInvalidRateLimitRule
	// ErrSessionNotFresh reports a Session outside the freshness window.
	ErrSessionNotFresh = core.ErrSessionNotFresh
	// ErrTokenInvalid reports a malformed, unknown or already-used Token.
	ErrTokenInvalid = core.ErrTokenInvalid
	// ErrTokenConsumed reports a Token that was already used; it also matches ErrTokenInvalid.
	ErrTokenConsumed = core.ErrTokenConsumed
	// ErrInvalidOTP reports a missing, malformed, unknown or expired email OTP.
	ErrInvalidOTP = core.ErrInvalidOTP
	// ErrOTPAlreadyUsed reports an email OTP that was already consumed.
	ErrOTPAlreadyUsed = core.ErrOTPAlreadyUsed
	// ErrInvalidMagicLink reports a missing, malformed, unknown or expired magic link.
	ErrInvalidMagicLink = core.ErrInvalidMagicLink
	// ErrMagicLinkAlreadyUsed reports a magic link that was already consumed.
	ErrMagicLinkAlreadyUsed = core.ErrMagicLinkAlreadyUsed
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
	// ErrInvalidKeyRing reports an empty, mixed or duplicate key ring.
	ErrInvalidKeyRing = core.ErrInvalidKeyRing
	// ErrInvalidRedirectPattern reports a malformed redirect pattern.
	ErrInvalidRedirectPattern = core.ErrInvalidRedirectPattern
	// ErrInvalidUsername reports a malformed or reserved Username.
	ErrInvalidUsername = core.ErrInvalidUsername
	// ErrUsernameTaken reports a Username already owned by another User.
	ErrUsernameTaken = core.ErrUsernameTaken
	// ErrLastAccount reports an unlink that would leave a User with no Account.
	ErrLastAccount = core.ErrLastAccount
	// ErrTOTPNotEnabled reports a Second factor operation for an unenrolled User.
	ErrTOTPNotEnabled = core.ErrTOTPNotEnabled
	// ErrTOTPInvalid reports an invalid TOTP code or Backup code.
	ErrTOTPInvalid = core.ErrTOTPInvalid
	// ErrTwoFactorRequired reports a sign-in that needs a Second factor.
	ErrTwoFactorRequired = core.ErrTwoFactorRequired
	// ErrTOTPNotConfigured reports a Second factor operation without configuration.
	ErrTOTPNotConfigured = core.ErrTOTPNotConfigured
	// ErrPasswordCompromised reports a password found in a known breach.
	ErrPasswordCompromised = core.ErrPasswordCompromised
	// ErrCaptchaRequired reports a missing captcha token.
	ErrCaptchaRequired = core.ErrCaptchaRequired
	// ErrCaptchaInvalid reports a rejected captcha token.
	ErrCaptchaInvalid = core.ErrCaptchaInvalid
	// ErrCaptchaUnavailable reports a captcha provider outage.
	ErrCaptchaUnavailable = core.ErrCaptchaUnavailable
	// ErrInvalidCaptchaEndpoint reports an unsupported captcha endpoint name.
	ErrInvalidCaptchaEndpoint = core.ErrInvalidCaptchaEndpoint
	// ErrRefreshReuse reports replay of a consumed Refresh token.
	ErrRefreshReuse = core.ErrRefreshReuse
	// ErrInvalidOAuthConfig reports invalid OAuth configuration.
	ErrInvalidOAuthConfig = core.ErrInvalidOAuthConfig
	// ErrOAuthProviderConflict reports duplicate or reserved provider IDs.
	ErrOAuthProviderConflict = core.ErrOAuthProviderConflict
	// ErrInvalidPasswordlessConfig reports a negative proof lifetime.
	ErrInvalidPasswordlessConfig = core.ErrInvalidPasswordlessConfig
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

var (
	// ErrForbidden reports an authorization denial.
	ErrForbidden = core.ErrForbidden
)

var (
	// ErrInvalidPasskeysConfig reports an invalid passkeys configuration.
	ErrInvalidPasskeysConfig = core.ErrInvalidPasskeysConfig
)

var (
	// ErrInvalidAuthorizationServerConfig reports a misconfigured Authorization server.
	ErrInvalidAuthorizationServerConfig = core.ErrInvalidAuthorizationServerConfig
	// ErrOAuthSlowDown reports that a device is polling too quickly.
	ErrOAuthSlowDown = core.ErrOAuthSlowDown
)

var (
	// ErrSSOConnectionNotFound reports an unknown SSO connection.
	ErrSSOConnectionNotFound = core.ErrSSOConnectionNotFound
	// ErrSSODomainNotVerified reports an unverified SSO domain.
	ErrSSODomainNotVerified = core.ErrSSODomainNotVerified
	// ErrSSOInvalidAssertion reports a rejected SSO assertion.
	ErrSSOInvalidAssertion = core.ErrSSOInvalidAssertion
	// ErrInvalidSSOConfig reports a misconfigured SSO feature.
	ErrInvalidSSOConfig = core.ErrInvalidSSOConfig
	// ErrSAMLInvalidAssertion reports a rejected SAML assertion.
	ErrSAMLInvalidAssertion = core.ErrSAMLInvalidAssertion
	// ErrSAMLConnectionNotFound reports an unknown SAML connection.
	ErrSAMLConnectionNotFound = core.ErrSAMLConnectionNotFound
	// ErrSAMLReplay reports a replayed SAML assertion.
	ErrSAMLReplay = core.ErrSAMLReplay
)

var (
	// ErrInvalidSCIMConfig reports a misconfigured SCIM server.
	ErrInvalidSCIMConfig = core.ErrInvalidSCIMConfig
	// ErrSCIMUnauthorized reports a rejected SCIM bearer token.
	ErrSCIMUnauthorized = core.ErrSCIMUnauthorized
)
