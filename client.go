package signet

import "context"

// Client is a configured Signet instance. It is safe for concurrent use and
// is intended to be created once at application startup.
type Client struct {
	cfg Config
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
	if cfg.PasswordHasher == nil {
		return nil, ErrMissingHasher
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
	return &Client{cfg: cfg}, nil
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
	return cfg
}
