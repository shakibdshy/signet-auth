package signet

import "errors"

var (
	// ErrNotFound reports that a User, Account, Session or Token does not exist.
	ErrNotFound = errors.New("signet: not found")
	// ErrInvalidCredentials reports a failed sign-in attempt.
	ErrInvalidCredentials = errors.New("signet: invalid credentials")
	// ErrEmailNotVerified reports a sign-in blocked by an unverified email.
	ErrEmailNotVerified = errors.New("signet: email not verified")
	// ErrRateLimited reports that an action exceeded its rate limit.
	ErrRateLimited = errors.New("signet: rate limited")
	// ErrTokenExpired reports a Token past its expiry.
	ErrTokenExpired = errors.New("signet: token expired")
	// ErrTokenInvalid reports a malformed, unknown or already-used Token.
	ErrTokenInvalid = errors.New("signet: token invalid")
	// ErrMissingStore reports that Config.Store was not supplied.
	ErrMissingStore = errors.New("signet: Config.Store is required")
	// ErrMissingMailer reports that Config.Mailer was not supplied.
	ErrMissingMailer = errors.New("signet: Config.Mailer is required")
	// ErrMissingHasher reports that Config.PasswordHasher was not supplied.
	ErrMissingHasher = errors.New("signet: Config.PasswordHasher is required")
	// ErrMissingRateLimiter reports that Config.RateLimiter was not supplied.
	ErrMissingRateLimiter = errors.New("signet: Config.RateLimiter is required")
	// ErrInsecureConfig reports a configuration that would weaken cookie
	// security without the explicit opt-in.
	ErrInsecureConfig = errors.New("signet: insecure configuration")
	// ErrInvalidEmail reports a missing or malformed email address.
	ErrInvalidEmail = errors.New("signet: invalid email")
	// ErrPasswordTooShort reports a password below the configured minimum.
	ErrPasswordTooShort = errors.New("signet: password too short")
	// ErrPasswordTooLong reports a password above the configured maximum.
	ErrPasswordTooLong = errors.New("signet: password too long")
	// ErrEmailAlreadyExists reports a sign-up for a registered email.
	ErrEmailAlreadyExists = errors.New("signet: email already exists")
)
