package signet

import "github.com/shakibdshy/signet/internal/core"

var (
	// ErrNotFound is re-exported from core.
	ErrNotFound = core.ErrNotFound
	// ErrInvalidCredentials is re-exported from core.
	ErrInvalidCredentials = core.ErrInvalidCredentials
	// ErrEmailNotVerified is re-exported from core.
	ErrEmailNotVerified = core.ErrEmailNotVerified
	// ErrRateLimited is re-exported from core.
	ErrRateLimited = core.ErrRateLimited
	// ErrTokenExpired is re-exported from core.
	ErrTokenExpired = core.ErrTokenExpired
	// ErrTokenInvalid is re-exported from core.
	ErrTokenInvalid = core.ErrTokenInvalid
	// ErrMissingStore is re-exported from core.
	ErrMissingStore = core.ErrMissingStore
	// ErrMissingMailer is re-exported from core.
	ErrMissingMailer = core.ErrMissingMailer
	// ErrMissingRateLimiter is re-exported from core.
	ErrMissingRateLimiter = core.ErrMissingRateLimiter
	// ErrInsecureConfig is re-exported from core.
	ErrInsecureConfig = core.ErrInsecureConfig
	// ErrInvalidEmail is re-exported from core.
	ErrInvalidEmail = core.ErrInvalidEmail
	// ErrPasswordTooShort is re-exported from core.
	ErrPasswordTooShort = core.ErrPasswordTooShort
	// ErrPasswordTooLong is re-exported from core.
	ErrPasswordTooLong = core.ErrPasswordTooLong
	// ErrEmailAlreadyExists is re-exported from core.
	ErrEmailAlreadyExists = core.ErrEmailAlreadyExists
	// ErrJWTDisabled is re-exported from core.
	ErrJWTDisabled = core.ErrJWTDisabled
	// ErrInvalidJWTAlgorithm is re-exported from core.
	ErrInvalidJWTAlgorithm = core.ErrInvalidJWTAlgorithm
	// ErrInvalidJWTKey is re-exported from core.
	ErrInvalidJWTKey = core.ErrInvalidJWTKey
	// ErrRefreshReuse is re-exported from core.
	ErrRefreshReuse = core.ErrRefreshReuse
	// ErrInvalidOAuthConfig is re-exported from core.
	ErrInvalidOAuthConfig = core.ErrInvalidOAuthConfig
	// ErrOAuthDisabled is re-exported from core.
	ErrOAuthDisabled = core.ErrOAuthDisabled
	// ErrOAuthProviderNotFound is re-exported from core.
	ErrOAuthProviderNotFound = core.ErrOAuthProviderNotFound
	// ErrOAuthInvalidState is re-exported from core.
	ErrOAuthInvalidState = core.ErrOAuthInvalidState
	// ErrOAuthRedirectNotAllowed is re-exported from core.
	ErrOAuthRedirectNotAllowed = core.ErrOAuthRedirectNotAllowed
	// ErrOAuthEmailNotVerified is re-exported from core.
	ErrOAuthEmailNotVerified = core.ErrOAuthEmailNotVerified
	// ErrOAuthAccountConflict is re-exported from core.
	ErrOAuthAccountConflict = core.ErrOAuthAccountConflict
	// ErrInvalidCSRFConfig is re-exported from core.
	ErrInvalidCSRFConfig = core.ErrInvalidCSRFConfig
)
