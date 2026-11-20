package signet

import (
	"context"
	"strings"

	"github.com/shakibdshy/signet/internal/auth"
	"github.com/shakibdshy/signet/internal/csrf"
	"github.com/shakibdshy/signet/internal/httpapi"
	"github.com/shakibdshy/signet/internal/oauth"
	"github.com/shakibdshy/signet/internal/session"
	"github.com/shakibdshy/signet/internal/token"
)

// Client is a configured Signet instance. It is safe for concurrent use and
// is intended to be created once at application startup.
type Client struct {
	cfg           Config
	dummyVerifier string
	jwtService    *token.JWTService
	csrf          *csrf.Guard
	tokens        *token.Service
	auth          *auth.Service
	sessions      *session.Service
	oauth         *oauth.Service
}

// New validates cfg and returns a ready Client. Required dependencies are
// reported with dedicated sentinel errors so callers can use errors.Is.
func New(cfg Config) (*Client, error) {
	if cfg.Store == nil {
		return nil, ErrMissingStore
	}
	if cfg.Mailer == nil {
		return nil, ErrMissingMailer
	}
	if cfg.RateLimiter == nil {
		return nil, ErrMissingRateLimiter
	}
	if (!cfg.Cookie.Secure || !cfg.Cookie.HttpOnly) && !cfg.InsecureAllowHTTPCookies {
		return nil, ErrInsecureConfig
	}

	cfg = withDefaults(cfg)
	if cfg.InsecureAllowHTTPCookies {
		// Security-relevant deviation: the explicit switch is required, and the
		// warning is emitted through the application's own logger.
		cfg.Logger.Warn("insecure cookie configuration enabled",
			"setting", "InsecureAllowHTTPCookies")
	}
	if cfg.InsecureDisableCSRF {
		cfg.Logger.Warn("insecure csrf protection disabled",
			"setting", "InsecureDisableCSRF")
	}
	dummy, err := cfg.PasswordHasher.Hash(context.Background(), dummyPassword)
	if err != nil {
		return nil, err
	}
	if cfg.OAuth != nil {
		if len(cfg.OAuth.Providers) == 0 || len(cfg.OAuth.StateKey) != 32 {
			return nil, ErrInvalidOAuthConfig
		}
	}
	if len(cfg.CSRFKey) != 32 && !cfg.JWTOnly {
		return nil, ErrInvalidCSRFConfig
	}
	var jwtCfg *JWTConfig
	if cfg.JWT != nil {
		jwtCopy := *cfg.JWT
		if err := token.ValidateJWTConfig(&jwtCopy); err != nil {
			return nil, err
		}
		jwtCfg = &jwtCopy
	}
	exempt := make(map[string]bool)
	for _, endpoint := range httpapi.Endpoints {
		if endpoint.Anonymous {
			exempt[endpoint.Name] = true
		}
	}
	sessionCookieName := cfg.Cookie.Name
	csrfCookieName := "signet_csrf"
	if cfg.Cookie.Secure && cfg.Cookie.Path == "/" && cfg.Cookie.Domain == "" {
		sessionCookieName = "__Host-" + sessionCookieName
		csrfCookieName = "__Host-" + csrfCookieName
	}
	c := &Client{
		cfg:           cfg,
		dummyVerifier: dummy,
		csrf: csrf.New(cfg.CSRFKey, cfg.Clock, csrfCookieName, sessionCookieName,
			cfg.Cookie.Path, cfg.Cookie.Domain, cfg.Cookie.Secure, cfg.Cookie.SameSite,
			strings.TrimRight(cfg.PathPrefix, "/"), exempt, cfg.InsecureDisableCSRF, cfg.Logger),
		tokens:   token.New(cfg.Store, cfg.Clock),
		sessions: session.New(cfg.Store, cfg.Clock, cfg.Session),
	}
	if jwtCfg != nil {
		c.jwtService = token.NewJWT(token.JWTDependencies{
			Config: jwtCfg, Store: cfg.Store, Clock: cfg.Clock,
			Limiter: cfg.RateLimiter, Logger: cfg.Logger, SignIn: c.SignIn,
		})
	}
	requireVerified := cfg.RequireVerifiedEmail == nil || *cfg.RequireVerifiedEmail
	sendVerification := cfg.SendVerificationOnSignUp == nil || *cfg.SendVerificationOnSignUp
	if cfg.OAuth != nil {
		c.oauth = oauth.New(cfg.OAuth, cfg.Store, cfg.Clock, cfg.RateLimiter, cfg.Logger, c.tokens, c.sessions)
	}
	c.auth = auth.New(auth.Dependencies{
		Store: cfg.Store, Hasher: cfg.PasswordHasher, Limiter: cfg.RateLimiter,
		Clock: cfg.Clock, Logger: cfg.Logger, Password: cfg.Password,
		RequireVerifiedEmail: requireVerified, SendVerificationOnSignUp: sendVerification,
		OnSignUp: cfg.OnSignUp, OnSignIn: cfg.OnSignIn,
		SendVerification: c.sendVerification, CreateSession: c.createSession,
		DummyVerifier: dummy,
	})
	return c, nil
}

func (c *Client) requireVerifiedEmail() bool {
	return c.cfg.RequireVerifiedEmail == nil || *c.cfg.RequireVerifiedEmail
}

func (c *Client) sendVerificationOnSignUp() bool {
	return c.cfg.SendVerificationOnSignUp == nil || *c.cfg.SendVerificationOnSignUp
}

func (c *Client) logInfo(msg string, attrs ...any) {
	c.cfg.Logger.Info(msg, append([]any{"at", c.cfg.Clock.Now()}, attrs...)...)
}

func (c *Client) logWarn(msg string, attrs ...any) {
	c.cfg.Logger.Warn(msg, append([]any{"at", c.cfg.Clock.Now()}, attrs...)...)
}

func noopHook(context.Context, *User) {}

func withDefaults(cfg Config) Config {
	defaults := DefaultConfig()
	if cfg.Clock == nil {
		cfg.Clock = defaults.Clock
	}
	if cfg.Logger == nil {
		cfg.Logger = defaults.Logger
	}
	if cfg.PasswordHasher == nil {
		cfg.PasswordHasher = defaults.PasswordHasher
	}
	if cfg.Cookie.Name == "" {
		cfg.Cookie.Name = defaults.Cookie.Name
	}
	if cfg.Cookie.Path == "" {
		cfg.Cookie.Path = defaults.Cookie.Path
	}
	if cfg.Cookie.SameSite == 0 {
		cfg.Cookie.SameSite = defaults.Cookie.SameSite
	}
	if cfg.Session.IdleTimeout == 0 {
		cfg.Session.IdleTimeout = defaults.Session.IdleTimeout
	}
	if cfg.Session.AbsoluteTimeout == 0 {
		cfg.Session.AbsoluteTimeout = defaults.Session.AbsoluteTimeout
	}
	if cfg.Password.MinLength == 0 {
		cfg.Password.MinLength = defaults.Password.MinLength
	}
	if cfg.Password.MaxLength == 0 {
		cfg.Password.MaxLength = defaults.Password.MaxLength
	}
	if cfg.PathPrefix == "" {
		cfg.PathPrefix = defaults.PathPrefix
	}
	if cfg.OnSignUp == nil {
		cfg.OnSignUp = noopHook
	}
	if cfg.OnSignIn == nil {
		cfg.OnSignIn = noopHook
	}
	if cfg.Templates == nil {
		cfg.Templates = DefaultTemplates
	}
	return cfg
}
