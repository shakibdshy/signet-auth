package signet

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// Config is the complete set of options for a Client. Use DefaultConfig for a
// secure baseline and override only what the application needs.
type Config struct {
	Store          Store
	Mailer         Mailer
	PasswordHasher PasswordHasher
	RateLimiter    RateLimiter
	Clock          Clock
	Logger         *slog.Logger
	// OnSignUp is notified after a successful sign-up. It receives a redacted
	// copy of the User and cannot abort the operation.
	OnSignUp func(context.Context, *User)
	// OnSignIn is notified after a successful sign-in. It receives a redacted
	// copy of the User and cannot abort the operation.
	OnSignIn                 func(context.Context, *User)
	Cookie                   CookieConfig
	Session                  SessionConfig
	Password                 PasswordConfig
	PathPrefix               string
	InsecureAllowHTTPCookies bool
	// InsecureDisableCSRF turns off the same-origin guard for cookie-based
	// state changes. It logs a warning and should only be used when another
	// layer provides equivalent protection.
	InsecureDisableCSRF bool
	// JWT enables optional bearer-token mode. When nil, only cookie sessions
	// are available.
	JWT *JWTConfig
	// RequireVerifiedEmail blocks sign-in until the User's email is verified.
	// Nil means true; set a pointer to false to opt out.
	RequireVerifiedEmail *bool
	// SendVerificationOnSignUp sends a verification email when a User is created.
	// Nil means true; set a pointer to false to opt out.
	SendVerificationOnSignUp *bool
	// AppURL is the application origin used to build absolute email links.
	AppURL string
	// Templates renders Signet's transactional email. Defaults to DefaultTemplates.
	Templates EmailTemplates
	// OAuth enables external sign-in providers. When nil, OAuth is disabled.
	OAuth *OAuthConfig
}

// CookieConfig controls the session cookie. Secure behaviour is the default.
type CookieConfig struct {
	Name     string
	Domain   string
	Path     string
	SameSite http.SameSite
	Secure   bool
	//nolint:revive // Matches the http.Cookie field name consumers already know.
	HttpOnly bool
}

// SessionConfig controls the lifetime of a Session.
type SessionConfig struct {
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
}

// PasswordConfig bounds the length of accepted passwords. The bounds exist to
// prevent hashing denial of service as well as weak passwords.
type PasswordConfig struct {
	MinLength int
	MaxLength int
}

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
		PathPrefix: "/",
		Templates:  DefaultTemplates,
	}
}
