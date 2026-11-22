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

// PasswordConfig bounds the length of accepted passwords. The bounds exist to
// prevent hashing denial of service as well as weak passwords.
type PasswordConfig = core.PasswordConfig

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
		Passwordless: &PasswordlessConfig{
			MagicLinkTTL: 5 * time.Minute,
			OTPTTL:       5 * time.Minute,
		},
		PathPrefix: "/",
		Templates:  DefaultTemplates,
	}
}
