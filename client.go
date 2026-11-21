package signet

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/shakibdshy/signet/internal/csrf"
	"github.com/shakibdshy/signet/internal/httpapi"
	"github.com/shakibdshy/signet/internal/oauth"
	"github.com/shakibdshy/signet/internal/ratelimit"
	"github.com/shakibdshy/signet/internal/secret"
	"github.com/shakibdshy/signet/internal/session"
	"github.com/shakibdshy/signet/internal/token"

	"github.com/shakibdshy/signet/internal/auth"
	"github.com/shakibdshy/signet/openapi"
)

// dummyPassword is hashed once at client construction for timing parity.
//
//nolint:gosec // G101: fixed timing-equalization input, not a credential.
const dummyPassword = "signet-anti-enumeration-dummy"

// DocsHandler returns an http.Handler serving the generated OpenAPI document at
// /openapi.json and an interactive reference at /. Mount it deliberately — it is
// not part of Client.Handler() and applications decide whether to protect it.
func DocsHandler() http.Handler {
	return httpapi.DocsHandler(openapi.Spec())
}

// Client is a configured Signet instance. It is safe for concurrent use and
// is intended to be created once at application startup.
type Client struct {
	cfg           Config
	dummyVerifier string
	jwtService    *token.JWTService
	csrf          *csrf.Guard
	cookies       *httpapi.Cookies
	tokens        *token.Service
	auth          *auth.Service
	verification  *auth.VerificationService
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
	limiter := ratelimit.New(cfg.RateLimiter, cfg.RateLimitRules)
	known := make(map[string]bool, len(httpapi.Endpoints))
	for _, endpoint := range httpapi.Endpoints {
		known[endpoint.Name] = true
	}
	for name := range cfg.RateLimitRules {
		if !known[name] {
			return nil, ErrInvalidRateLimitRule
		}
	}
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
	guard := csrf.New(cfg.CSRFKey, cfg.Clock, csrfCookieName, sessionCookieName,
		cfg.Cookie.Path, cfg.Cookie.Domain, cfg.Cookie.Secure, cfg.Cookie.SameSite,
		strings.TrimRight(cfg.PathPrefix, "/"), exempt, cfg.InsecureDisableCSRF, cfg.Logger)
	c := &Client{
		cfg:           cfg,
		dummyVerifier: dummy,
		csrf:          guard,
		cookies: httpapi.NewCookies(guard, sessionCookieName, cfg.Cookie.Path, cfg.Cookie.Domain,
			cfg.Cookie.Secure, cfg.Cookie.HttpOnly, cfg.Cookie.SameSite, cfg.JWTOnly),
		tokens:   token.New(cfg.Store, cfg.Clock),
		sessions: session.New(cfg.Store, cfg.Clock, cfg.Session),
	}
	if jwtCfg != nil {
		c.jwtService = token.NewJWT(token.JWTDependencies{
			Config: jwtCfg, Store: cfg.Store, Clock: cfg.Clock,
			Limiter: limiter, Logger: cfg.Logger, SignIn: c.SignIn,
		})
	}
	requireVerified := cfg.RequireVerifiedEmail == nil || *cfg.RequireVerifiedEmail
	sendVerification := cfg.SendVerificationOnSignUp == nil || *cfg.SendVerificationOnSignUp
	if cfg.OAuth != nil {
		c.oauth = oauth.New(cfg.OAuth, cfg.Store, cfg.Clock, limiter, cfg.Logger, c.tokens, c.sessions)
	}
	c.verification = auth.NewVerification(auth.VerificationDependencies{
		Store: cfg.Store, Tokens: c.tokens, Mailer: cfg.Mailer, Templates: cfg.Templates,
		Clock: cfg.Clock, Limiter: limiter, Logger: cfg.Logger,
		AppURL: cfg.AppURL, Password: cfg.Password, Hasher: cfg.PasswordHasher,
	})
	c.auth = auth.New(auth.Dependencies{
		Store: cfg.Store, Hasher: cfg.PasswordHasher, Limiter: limiter,
		Clock: cfg.Clock, Logger: cfg.Logger, Password: cfg.Password,
		RequireVerifiedEmail: requireVerified, SendVerificationOnSignUp: sendVerification,
		OnSignUp: cfg.OnSignUp, OnSignIn: cfg.OnSignIn,
		SendVerification: c.verification.SendVerificationForUser, CreateSession: c.createSession,
		DummyVerifier: dummy,
	})
	return c, nil
}

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

func noopHook(context.Context, *User) {}

func redactedUser(user *User) *User {
	redactedCopy := *user
	redactedCopy.Email = ""
	redactedCopy.Name = ""
	return &redactedCopy
}

// SignUp creates a User and its credential Account, returning the new User.
func (c *Client) SignUp(ctx context.Context, in SignUpInput) (*SignUpResult, error) {
	return c.auth.SignUp(ctx, in)
}

// SignIn verifies a password, rehashes a stale verifier, creates a Session and
// returns its raw Session token. Failures are deliberately generic so callers
// cannot tell whether an email is registered.
func (c *Client) SignIn(ctx context.Context, in SignInInput) (*SignInResult, error) {
	return c.auth.SignIn(ctx, in)
}

// SignOut revokes the Session identified by a Session token. Unknown or
// already-revoked tokens are a successful no-op so clients need no special
// handling for repeated logouts.
func (c *Client) SignOut(ctx context.Context, in SignOutInput) error {
	return c.auth.SignOut(ctx, in)
}

// VerifyFreshSession reports whether a Session was authenticated within the configured freshness window.
func (c *Client) VerifyFreshSession(ctx context.Context, token string) error {
	fresh, err := c.sessions.IsFresh(ctx, token)
	if err != nil {
		return err
	}
	if !fresh {
		return ErrSessionNotFresh
	}
	return nil
}

// RequireFreshSession protects a handler with a fresh-Session check.
func (c *Client) RequireFreshSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(c.cookies.Name())
		if err != nil || cookie.Value == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := c.VerifyFreshSession(r.Context(), cookie.Value); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequestUserDeletion sends a single-use proof to the User's current email.
func (c *Client) RequestUserDeletion(ctx context.Context, in RequestDeleteUserInput) error {
	return c.verification.RequestUserDeletion(ctx, in)
}

// DeleteUser consumes the proof and removes the User and all child records.
func (c *Client) DeleteUser(ctx context.Context, in ConfirmDeleteUserInput) error {
	return c.verification.DeleteUser(ctx, in)
}

// RequestEmailChange issues a single-use proof to a new email address.
func (c *Client) RequestEmailChange(ctx context.Context, in ChangeEmailInput) error {
	return c.verification.RequestEmailChange(ctx, in)
}

// VerifyEmailChange consumes an email-change proof and commits the new address.
func (c *Client) VerifyEmailChange(ctx context.Context, in VerifyEmailChangeInput) error {
	return c.verification.VerifyEmailChange(ctx, in)
}

// ChangePassword replaces an authenticated User's password and revokes their Sessions and Tokens.
func (c *Client) ChangePassword(ctx context.Context, in ChangePasswordInput) error {
	return c.verification.ChangePassword(ctx, in)
}

// SendVerification sends a verification email. It succeeds for unknown emails
// so callers cannot enumerate registered Users.
func (c *Client) SendVerification(ctx context.Context, in SendVerificationInput) error {
	return c.verification.SendVerification(ctx, in)
}

// VerifyEmail consumes a verification Token and marks its User verified.
func (c *Client) VerifyEmail(ctx context.Context, in VerifyEmailInput) error {
	return c.verification.VerifyEmail(ctx, in)
}

// SendPasswordReset sends a reset email. It succeeds for unknown emails so
// callers cannot enumerate registered Users.
func (c *Client) SendPasswordReset(ctx context.Context, in SendPasswordResetInput) error {
	return c.verification.SendPasswordReset(ctx, in)
}

// ResetPassword consumes a reset Token and replaces the credential verifier.
func (c *Client) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	return c.verification.ResetPassword(ctx, in)
}

// OAuthStart begins an Authorization Code flow with PKCE.
func (c *Client) OAuthStart(ctx context.Context, in OAuthStartInput) (*OAuthStartResult, error) {
	if c.cfg.OAuth == nil {
		return nil, ErrOAuthDisabled
	}
	return c.oauth.Start(ctx, in)
}

// OAuthCallback redeems the provider code.
func (c *Client) OAuthCallback(ctx context.Context, in OAuthCallbackInput) (*OAuthCallbackResult, error) {
	if c.cfg.OAuth == nil {
		return nil, ErrOAuthDisabled
	}
	result, err := c.oauth.Callback(ctx, in)
	if err != nil {
		return nil, err
	}
	// Application hooks are a root concern. Fire the same redacted sign-in
	// event as the password flow, but only once a User actually signed in —
	// a pending link token is not a completed sign-in.
	if result.User != nil {
		c.cfg.OnSignIn(ctx, redactedUser(result.User))
	}
	return result, nil
}

// LinkOAuthAccount links a provider Account after explicit consent.
func (c *Client) LinkOAuthAccount(ctx context.Context, in LinkOAuthAccountInput) error {
	if c.cfg.OAuth == nil {
		return ErrOAuthDisabled
	}
	return c.oauth.LinkAccount(ctx, in)
}

// ExchangeToken issues a TokenPair for credentials, or rotates a Refresh token.
func (c *Client) ExchangeToken(ctx context.Context, in TokenInput) (*TokenPair, error) {
	if c.jwtService == nil {
		return nil, ErrJWTDisabled
	}
	return c.jwtService.Exchange(ctx, in)
}

// VerifyAccessToken validates a bearer token and returns its User.
func (c *Client) VerifyAccessToken(ctx context.Context, raw string) (*User, error) {
	if c.jwtService == nil {
		return nil, ErrJWTDisabled
	}
	return c.jwtService.VerifyAccessToken(ctx, raw)
}

// ListSessions returns the Sessions belonging to a User.
func (c *Client) ListSessions(ctx context.Context, in ListSessionsInput) (*ListSessionsResult, error) {
	sessions, err := c.sessions.List(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	return &ListSessionsResult{Sessions: sessions}, nil
}

// RevokeSession revokes one Session. Unknown IDs are a no-op.
func (c *Client) RevokeSession(ctx context.Context, in RevokeSessionInput) error {
	return c.sessions.Revoke(ctx, in.SessionID)
}

// RevokeAllSessions revokes every Session of a User.
func (c *Client) RevokeAllSessions(ctx context.Context, in RevokeAllSessionsInput) error {
	return c.sessions.RevokeAll(ctx, in.UserID)
}

func (c *Client) createSession(ctx context.Context, userID string) (string, error) {
	return c.sessions.Create(ctx, userID)
}

func digestSecret(token string) string { return secret.Digest(token) }

// RequireAuth is standard middleware that resolves the Session cookie,
// enforces its deadlines and attaches the authenticated User to the request.
func (c *Client) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := c.authenticate(w, r, true)
		if !ok {
			return
		}
		ctx := httpapi.WithUser(r.Context(), user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuth attaches the authenticated User when a valid Session is
// present and passes the request through otherwise.
func (c *Client) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := c.authenticate(w, r, false)
		if ok {
			ctx := httpapi.WithUser(r.Context(), user)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func (c *Client) currentSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(c.cookies.Name())
	if err != nil || cookie.Value == "" {
		return nil, ErrNotFound
	}
	return c.sessions.ByHash(r.Context(), digestSecret(cookie.Value))
}

func (c *Client) authenticate(w http.ResponseWriter, r *http.Request, required bool) (*User, bool) {
	if c.csrf.Guard(w, r) {
		return nil, false
	}
	deny := func() (*User, bool) {
		if required {
			writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		}
		return nil, false
	}
	cookie, err := r.Cookie(c.cookies.Name())
	if err != nil || cookie.Value == "" {
		return deny()
	}
	user, err := c.sessions.Resolve(r.Context(), cookie.Value)
	if err != nil {
		return deny()
	}
	return user, true
}

// Handler returns a plain http.Handler serving Signet's authentication endpoints.
func (c *Client) Handler() http.Handler {
	return httpapi.New(httpAdapter{Client: c}, c.cfg.PathPrefix).Handler()
}

// httpAdapter exposes the internal helpers the HTTP module needs without
// changing the public Client interface.
type httpAdapter struct{ *Client }

func (a httpAdapter) CSRFGuard(w http.ResponseWriter, r *http.Request) bool {
	return a.csrf.Guard(w, r)
}
func (a httpAdapter) ServeCSRFToken(w http.ResponseWriter, r *http.Request) { a.csrf.ServeToken(w, r) }
func (a httpAdapter) SetSessionCookies(w http.ResponseWriter, token string) (string, error) {
	return a.cookies.SetSessionAndCSRF(w, token)
}
func (a httpAdapter) CookieName() string { return a.cookies.Name() }
func (a httpAdapter) NewSessionCookie(token string, expiring bool) *http.Cookie {
	return a.cookies.SessionCookie(token, expiring)
}
func (a httpAdapter) ClearSessionCookie(w http.ResponseWriter) { a.cookies.ClearSessionCookie(w) }
func (a httpAdapter) Authenticate(w http.ResponseWriter, r *http.Request, required bool) (*User, bool) {
	return a.authenticate(w, r, required)
}
func (a httpAdapter) CurrentSession(r *http.Request) (*Session, error) {
	return a.currentSession(r)
}

// UserFromContext returns the authenticated User carried by a request context.
func UserFromContext(ctx context.Context) (*User, bool) {
	user, ok := httpapi.UserFromContext(ctx)
	return user, ok
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}
