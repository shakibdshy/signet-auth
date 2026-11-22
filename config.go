package signet

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/shakibdshy/signet/internal/core"
)

// Config is the complete set of options for a Client. Use DefaultConfig for a
// secure baseline and override only what the application needs.
type Config = core.Config

// CookieConfig controls the session cookie. Secure behaviour is the default.
type CookieConfig = core.CookieConfig

// SessionConfig controls the lifetime of a Session.
type SessionConfig = core.SessionConfig

// SessionCache optionally short-circuits a Session lookup. The Store remains authoritative.
type SessionCache = core.SessionCache

// CachedSession is a short-lived copy of a resolved Session.
type CachedSession = core.CachedSession

// PasswordConfig bounds the length of accepted passwords. The bounds exist to
// prevent hashing denial of service as well as weak passwords.
type PasswordConfig = core.PasswordConfig

// UsernameConfig controls Username normalization and validation.
type UsernameConfig = core.UsernameConfig

// AccountConfig controls account-management safeguards.
type AccountConfig = core.AccountConfig

// TOTPConfig controls TOTP code generation and verification.
type TOTPConfig = core.TOTPConfig

// TOTPStore persists Second factor enrollment state.
type TOTPStore = core.TOTPStore

// TOTPState is the persisted state of a Second factor enrollment.
type TOTPState = core.TOTPState

// BreachChecker reports whether a password has appeared in a known breach.
type BreachChecker = core.BreachChecker

// CaptchaVerifier verifies a captcha token for a client request.
type CaptchaVerifier = core.CaptchaVerifier

// AuditSink receives Audit events.
type AuditSink = core.AuditSink

// AuditEvent is a security-relevant action and its outcome.
type AuditEvent = core.AuditEvent

// LastSignInMethodConfig controls the Last sign-in method cookie.
type LastSignInMethodConfig = core.LastSignInMethodConfig

// PasswordlessConfig controls magic-link and email-OTP sign-in.
type PasswordlessConfig = core.PasswordlessConfig

// DefaultConfig returns a Config with secure defaults. A Store, Mailer,
// PasswordHasher and RateLimiter must still be supplied before New will
// succeed.
func DefaultConfig() Config {
	return Config{
		Clock:          SystemClock{},
		Logger:         slog.Default(),
		PasswordHasher: Argon2idHasher{},
		Cookie: CookieConfig{
			Name:     "signet_session",
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			Secure:   true,
			HttpOnly: true,
		},
		Session: SessionConfig{
			IdleTimeout:     30 * time.Minute,
			AbsoluteTimeout: 24 * time.Hour,
		},
		Password: PasswordConfig{
			MinLength: 8,
			MaxLength: 128,
		},
		Username: &UsernameConfig{MinLength: 3, MaxLength: 30},
		Accounts: &AccountConfig{FreshWindow: 5 * time.Minute},
		TOTP:     &TOTPConfig{Digits: 6, Period: 30, Window: 1},
		Passwordless: &PasswordlessConfig{
			MagicLinkTTL: 5 * time.Minute,
			OTPTTL:       5 * time.Minute,
		},
		PathPrefix: "/",
		Templates:  DefaultTemplates,
	}
}
