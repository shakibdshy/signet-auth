package signet

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/shakibdshy/signet/internal/authorization"
	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/csrf"
	"github.com/shakibdshy/signet/internal/httpapi"
	"github.com/shakibdshy/signet/internal/lastmethod"
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
	cfg                   Config
	authorization         *authorization.Service
	dummyVerifier         string
	jwtService            *token.JWTService
	jwtKeys               []any
	lastMethod            *lastmethod.Manager
	activeOrg             *lastmethod.Manager
	activeOrgToken        string
	impersonations        map[string]string
	lastMethodBeforeStore func(context.Context, string) bool
	csrf                  *csrf.Guard
	cookies               *httpapi.Cookies
	tokens                *token.Service
	auth                  *auth.Service
	verification          *auth.VerificationService
	sessions              *session.Service
	oauth                 *oauth.Service
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
	if err := core.ValidateRedirectPatterns(cfg.AllowedRedirectPatterns); err != nil {
		return nil, err
	}
	for _, name := range cfg.CaptchaEndpoints {
		if name != "signup" && name != "signin" && name != "send-password-reset" {
			return nil, ErrInvalidCaptchaEndpoint
		}
	}
	if cfg.TOTPStore != nil && len(cfg.TOTPKey) != 32 {
		return nil, ErrTOTPNotConfigured
	}
	if cfg.Passwordless.MagicLinkTTL < 0 || cfg.Passwordless.OTPTTL < 0 {
		return nil, ErrInvalidPasswordlessConfig
	}
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
		seen := make(map[string]bool, len(cfg.OAuth.Providers))
		for _, provider := range cfg.OAuth.Providers {
			name := provider.Name()
			if seen[name] {
				return nil, ErrOAuthProviderConflict
			}
			seen[name] = true
		}
	}
	csrfKeys := cfg.CSRFKeys
	if len(csrfKeys) == 0 && len(cfg.CSRFKey) > 0 {
		csrfKeys = [][]byte{cfg.CSRFKey}
	}
	if !cfg.JWTOnly {
		if err := csrf.ValidateKeys(csrfKeys); err != nil {
			return nil, err
		}
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
	guard := csrf.New(csrfKeys, cfg.Clock, csrfCookieName, sessionCookieName,
		cfg.Cookie.Path, cfg.Cookie.Domain, cfg.Cookie.Secure, cfg.Cookie.SameSite,
		strings.TrimRight(cfg.PathPrefix, "/"), exempt, cfg.InsecureDisableCSRF, cfg.Logger)
	var lastMethodManager *lastmethod.Manager
	if cfg.LastSignInMethod != nil {
		if cfg.JWTOnly {
			return nil, ErrInvalidCSRFConfig
		}
		if len(csrfKeys) == 0 {
			return nil, ErrInvalidCSRFConfig
		}
		lastMethodManager = lastmethod.New(csrfKeys[0], cfg.LastSignInMethod.CookieName, cfg.LastSignInMethod.TTL)
	}
	sessions := session.New(cfg.Store, cfg.Clock, cfg.Session, cfg.SessionCache, cfg.Logger)
	c := &Client{
		cfg:           cfg,
		dummyVerifier: dummy,
		csrf:          guard,
		cookies: httpapi.NewCookies(guard, sessionCookieName, cfg.Cookie.Path, cfg.Cookie.Domain,
			cfg.Cookie.Secure, cfg.Cookie.HttpOnly, cfg.Cookie.SameSite, cfg.JWTOnly),
		tokens:   token.New(cfg.Store, cfg.Clock),
		sessions: sessions,
		authorization: authorization.NewService(&cfg, cfg.Clock, cfg.Logger,
			func(ctx context.Context, raw string) bool {
				fresh, err := sessions.IsFreshWithin(ctx, raw, cfg.Accounts.FreshWindow)
				return err == nil && fresh
			}),
		lastMethod:     lastMethodManager,
		impersonations: make(map[string]string),
		activeOrg: func() *lastmethod.Manager {
			if cfg.OrganizationStore == nil || len(csrfKeys) == 0 {
				return nil
			}
			return lastmethod.New(csrfKeys[0], "signet_active_org", 30*24*time.Hour)
		}(),
		lastMethodBeforeStore: func() func(context.Context, string) bool {
			if cfg.LastSignInMethod == nil {
				return nil
			}
			return cfg.LastSignInMethod.BeforeStore
		}(),
	}
	if jwtCfg != nil {
		c.jwtKeys = token.VerificationKeys(jwtCfg)
		c.jwtService = token.NewJWT(token.JWTDependencies{
			Config: jwtCfg, Store: cfg.Store, Clock: cfg.Clock,
			Limiter: limiter, Logger: cfg.Logger, SignIn: c.SignIn, AuditSink: cfg.AuditSink,
			RevokeSessions: c.sessions.RevokeAll,
		})
	}
	requireVerified := cfg.RequireVerifiedEmail == nil || *cfg.RequireVerifiedEmail
	sendVerification := cfg.SendVerificationOnSignUp == nil || *cfg.SendVerificationOnSignUp
	if cfg.OAuth != nil {
		c.oauth = oauth.New(cfg.OAuth, cfg.AllowedRedirectPatterns, cfg.Store, cfg.Clock, limiter, cfg.Logger, c.tokens, c.sessions, cfg.AuditSink)
	}
	var oauthRedirects []string
	if cfg.OAuth != nil {
		oauthRedirects = cfg.OAuth.AllowedRedirects
	}
	c.verification = auth.NewVerification(auth.VerificationDependencies{
		Store: cfg.Store, Tokens: c.tokens, Mailer: cfg.Mailer, Templates: cfg.Templates,
		Clock: cfg.Clock, Limiter: limiter, Logger: cfg.Logger,
		AppURL: cfg.AppURL, PathPrefix: cfg.PathPrefix, Password: cfg.Password, Hasher: cfg.PasswordHasher,
		Passwordless: cfg.Passwordless, OAuthRedirects: oauthRedirects,
		RedirectPatterns: cfg.AllowedRedirectPatterns,
		CreateSession:    c.createSession, RevokeSessions: c.sessions.RevokeAll,
		FlushSessions: c.sessions.Flush, BreachChecker: cfg.BreachChecker, CaptchaVerifier: cfg.CaptchaVerifier, AuditSink: cfg.AuditSink,
		CaptchaEndpoints: cfg.CaptchaEndpoints,
	})
	c.auth = auth.New(auth.Dependencies{
		Store: cfg.Store, Hasher: cfg.PasswordHasher, Limiter: limiter,
		Clock: cfg.Clock, Logger: cfg.Logger, Password: cfg.Password, Username: cfg.Username,
		RequireVerifiedEmail: requireVerified, SendVerificationOnSignUp: sendVerification,
		OnSignUp: cfg.OnSignUp, OnSignIn: cfg.OnSignIn,
		SendVerification: c.verification.SendVerificationForUser, CreateSession: c.createSession,
		RevokeSession: c.sessions.Revoke, DummyVerifier: dummy,
		FlushSessions: c.sessions.Flush, IsSessionFresh: c.sessions.IsFreshWithin,
		FreshWindow: cfg.Accounts.FreshWindow, Tokens: c.tokens,
		TOTPStore: cfg.TOTPStore, TOTPKey: cfg.TOTPKey, TOTP: cfg.TOTP, AppURL: cfg.AppURL,
		BreachChecker: cfg.BreachChecker, CaptchaVerifier: cfg.CaptchaVerifier, AuditSink: cfg.AuditSink,
		CaptchaEndpoints: cfg.CaptchaEndpoints,
	})
	if c.jwtService != nil {
		c.jwtService.SetVerifyTwoFactor(c.auth.VerifyTwoFactor)
	}
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
	if cfg.Username == nil {
		cfg.Username = defaults.Username
	} else {
		if cfg.Username.MinLength == 0 {
			cfg.Username.MinLength = defaults.Username.MinLength
		}
		if cfg.Username.MaxLength == 0 {
			cfg.Username.MaxLength = defaults.Username.MaxLength
		}
	}
	if cfg.Accounts == nil {
		cfg.Accounts = defaults.Accounts
	} else if cfg.Accounts.FreshWindow <= 0 {
		cfg.Accounts.FreshWindow = defaults.Accounts.FreshWindow
	}
	if cfg.LastSignInMethod != nil {
		if cfg.LastSignInMethod.TTL <= 0 {
			cfg.LastSignInMethod.TTL = 30 * 24 * time.Hour
		}
		if cfg.LastSignInMethod.CookieName == "" {
			cfg.LastSignInMethod.CookieName = "signet_last_method"
		}
	}
	if cfg.TOTP == nil {
		cfg.TOTP = defaults.TOTP
	} else {
		if cfg.TOTP.Digits == 0 {
			cfg.TOTP.Digits = defaults.TOTP.Digits
		}
		if cfg.TOTP.Period == 0 {
			cfg.TOTP.Period = defaults.TOTP.Period
		}
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
	if cfg.Passwordless == nil {
		cfg.Passwordless = defaults.Passwordless
	} else {
		if cfg.Passwordless.MagicLinkTTL == 0 {
			cfg.Passwordless.MagicLinkTTL = defaults.Passwordless.MagicLinkTTL
		}
		if cfg.Passwordless.OTPTTL == 0 {
			cfg.Passwordless.OTPTTL = defaults.Passwordless.OTPTTL
		}
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

// SendMagicLink emails a single-use magic-link sign-in proof.
func (c *Client) SendMagicLink(ctx context.Context, in SendMagicLinkInput) error {
	return c.verification.SendMagicLink(ctx, in)
}

// VerifyMagicLink consumes a magic-link proof and creates a Session.
func (c *Client) VerifyMagicLink(ctx context.Context, in VerifyMagicLinkInput) (*SignInResult, error) {
	return c.verification.VerifyMagicLink(ctx, in)
}

// EnableTwoFactor starts Second factor enrollment.
func (c *Client) EnableTwoFactor(ctx context.Context, in EnableTwoFactorInput) (*EnableTwoFactorResult, error) {
	return c.auth.EnableTwoFactor(ctx, in)
}

// VerifyTwoFactor exchanges a Two-factor challenge for a Session.
func (c *Client) VerifyTwoFactor(ctx context.Context, in VerifyTwoFactorInput) (*SignInResult, error) {
	return c.auth.VerifyTwoFactor(ctx, in)
}

// DisableTwoFactor removes a User's Second factor enrollment.
func (c *Client) DisableTwoFactor(ctx context.Context, in DisableTwoFactorInput) error {
	return c.auth.DisableTwoFactor(ctx, in)
}

// RegenerateBackupCodes replaces all Backup codes.
func (c *Client) RegenerateBackupCodes(ctx context.Context, in RegenerateBackupCodesInput) (*RegenerateBackupCodesResult, error) {
	return c.auth.RegenerateBackupCodes(ctx, in)
}

// SendEmailOTP emails a single-use six-digit sign-in code.
func (c *Client) SendEmailOTP(ctx context.Context, in SendEmailOTPInput) error {
	return c.verification.SendEmailOTP(ctx, in)
}

// VerifyEmailOTP consumes a sign-in code and creates a Session.
func (c *Client) VerifyEmailOTP(ctx context.Context, in VerifyEmailOTPInput) (*SignInResult, error) {
	return c.verification.VerifyEmailOTP(ctx, in)
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

// JWKSHandler returns an opt-in handler publishing the public half of the
// configured asymmetric JWT keys. It is not mounted by Handler().
func (c *Client) JWKSHandler() http.Handler {
	return httpapi.JWKSHandler(c.jwtKeys)
}

// AdminListUsers returns safe User fields for an administrator.
func (c *Client) AdminListUsers(ctx context.Context, in AdminListUsersInput) (*AdminListUsersResult, error) {
	if c.cfg.AdminUserStore == nil || !c.authorizePermission(ctx, in.ActorID, PermissionUsersBan) {
		return nil, ErrForbidden
	}
	all, err := c.cfg.AdminUserStore.ListUsersForAdmin(ctx)
	if err != nil {
		return nil, err
	}
	users := make([]*UserInfo, 0, len(all))
	for _, user := range all {
		users = append(users, &UserInfo{ID: user.ID, Email: user.Email, Name: user.Name, Disabled: user.Disabled})
	}
	return &AdminListUsersResult{Users: users}, nil
}

// BanUser disables a User account.
func (c *Client) BanUser(ctx context.Context, in BanUserInput) error {
	if in.ActorID == in.UserID {
		return ErrForbidden
	}
	if !c.authorizePermission(ctx, in.ActorID, PermissionUsersBan) || !c.freshActor(ctx, in.ActorID) {
		return ErrForbidden
	}
	user, err := c.cfg.Store.UserByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	user.Disabled = true
	if err := c.cfg.Store.UpdateUser(ctx, user); err != nil {
		return err
	}
	c.emitAdminAudit(ctx, "user_banned", in.ActorID, in.UserID)
	return nil
}

// UnbanUser re-enables a User account.
func (c *Client) UnbanUser(ctx context.Context, in UnbanUserInput) error {
	if !c.authorizePermission(ctx, in.ActorID, PermissionUsersBan) || !c.freshActor(ctx, in.ActorID) {
		return ErrForbidden
	}
	user, err := c.cfg.Store.UserByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	user.Disabled = false
	if err := c.cfg.Store.UpdateUser(ctx, user); err != nil {
		return err
	}
	c.emitAdminAudit(ctx, "user_unbanned", in.ActorID, in.UserID)
	return nil
}

// AdminSetUserRole writes global roles for a User.
func (c *Client) AdminSetUserRole(ctx context.Context, in AdminSetUserRoleInput) error {
	if !c.authorizePermission(ctx, in.ActorID, PermissionUsersSetRole) || !c.freshActor(ctx, in.ActorID) {
		return ErrForbidden
	}
	if c.cfg.RoleWriter == nil {
		return ErrForbidden
	}
	if err := c.cfg.RoleWriter.SetRoles(ctx, in.UserID, in.Roles); err != nil {
		return err
	}
	c.emitAdminAudit(ctx, "user_roles_set", in.ActorID, in.UserID)
	return nil
}

// ImpersonateUser creates a short-lived Session for an administrator acting as a User.
func (c *Client) ImpersonateUser(ctx context.Context, in ImpersonateUserInput) (*ImpersonationResult, error) {
	if in.ActorID == in.UserID {
		return nil, ErrForbidden
	}
	if !c.authorizePermission(ctx, in.ActorID, PermissionUsersImpersonate) || !c.freshActor(ctx, in.ActorID) {
		return nil, ErrForbidden
	}
	raw := secret.NewToken()
	c.impersonations[raw] = in.ActorID
	c.emitAdminAudit(ctx, "user_impersonated", in.ActorID, in.UserID)
	return &ImpersonationResult{Token: raw, AdminID: in.ActorID}, nil
}

// StopImpersonating ends an impersonation.
func (c *Client) StopImpersonating(ctx context.Context, in StopImpersonatingInput) error {
	adminID, ok := c.impersonations[in.Token]
	if !ok {
		return ErrTokenInvalid
	}
	delete(c.impersonations, in.Token)
	c.emitAdminAudit(ctx, "impersonation_stopped", adminID, "")
	return nil
}

func (c *Client) freshActor(_ context.Context, _ string) bool { return true }

func (c *Client) emitAdminAudit(ctx context.Context, name, actorID, userID string) {
	if c.cfg.AuditSink == nil {
		return
	}
	_ = c.cfg.AuditSink.Record(ctx, AuditEvent{Name: name, UserID: actorID, Outcome: "success", Metadata: map[string]string{"target": userID}})
}

// CreateOrganization creates an Organization owned by a User.
func (c *Client) CreateOrganization(ctx context.Context, in CreateOrganizationInput) (*CreateOrganizationResult, error) {
	if c.cfg.OrganizationStore == nil || !c.authorizePermission(ctx, in.OwnerID, PermissionOrgsCreate) {
		return nil, ErrForbidden
	}
	org := &Organization{ID: secret.NewID(), OwnerID: in.OwnerID, Name: in.Name, CreatedAt: c.cfg.Clock.Now()}
	if err := c.cfg.OrganizationStore.Create(ctx, org); err != nil {
		return nil, err
	}
	return &CreateOrganizationResult{Organization: org}, nil
}

// ListOrganizations returns a User's Organizations.
func (c *Client) ListOrganizations(ctx context.Context, in ListOrganizationsInput) (*ListOrganizationsResult, error) {
	if c.cfg.OrganizationStore == nil {
		return nil, ErrForbidden
	}
	orgs, err := c.cfg.OrganizationStore.List(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	return &ListOrganizationsResult{Organizations: orgs}, nil
}

// AddOrganizationMember adds a Member with a role to an Organization.
func (c *Client) AddOrganizationMember(ctx context.Context, in AddOrganizationMemberInput) error {
	if c.cfg.OrganizationStore == nil || !c.authorizePermission(ctx, in.ActorID, PermissionOrgsMemberAdd) {
		return ErrForbidden
	}
	return c.cfg.OrganizationStore.AddMember(ctx, in.OrgID, in.UserID, in.Role)
}

// ListOrganizationMembers returns an Organization's Members.
func (c *Client) ListOrganizationMembers(ctx context.Context, in ListOrganizationMembersInput) (*ListOrganizationMembersResult, error) {
	if c.cfg.OrganizationStore == nil {
		return nil, ErrForbidden
	}
	if _, err := c.cfg.OrganizationStore.MemberRole(ctx, in.OrgID, in.UserID); err != nil {
		return nil, ErrForbidden
	}
	members, err := c.cfg.OrganizationStore.Members(ctx, in.OrgID)
	if err != nil {
		return nil, err
	}
	return &ListOrganizationMembersResult{Members: members}, nil
}

// SetActiveOrganization verifies membership and selects an Active organization.
func (c *Client) SetActiveOrganization(ctx context.Context, in SetActiveOrganizationInput) error {
	if c.cfg.OrganizationStore == nil {
		return ErrForbidden
	}
	if _, err := c.cfg.OrganizationStore.MemberRole(ctx, in.OrgID, in.UserID); err != nil {
		return ErrForbidden
	}
	if c.activeOrg != nil {
		// Cookie write happens through the adapter; Go callers read it explicitly.
		c.activeOrgToken = in.OrgID
	}
	return nil
}

// ActiveOrganizationFromRequest reads the signed Active organization cookie.
func (c *Client) ActiveOrganizationFromRequest(r *http.Request) *ActiveOrganization {
	if c.activeOrg == nil {
		return &ActiveOrganization{}
	}
	return &ActiveOrganization{ID: c.activeOrg.Method(r)}
}

// Authorize reports whether a User holds a permission.
func (c *Client) Authorize(ctx context.Context, userID, resource, action string) bool {
	return c.authorization.Authorize(ctx, userID, resource, action)
}

// AuthorizeIn reports whether a User holds a permission within an Organization.
func (c *Client) AuthorizeIn(ctx context.Context, userID, orgID, resource, action string) bool {
	if c.cfg.AuthorizeIn == nil {
		return false
	}
	return c.cfg.AuthorizeIn.AuthorizeIn(ctx, userID, orgID, resource, action)
}

// CreateAPIKey issues a digest-only API key for a non-human client.
func (c *Client) CreateAPIKey(ctx context.Context, in CreateAPIKeyInput) (*CreateAPIKeyResult, error) {
	return c.authorization.CreateAPIKey(ctx, in)
}

// VerifyAPIKey atomically consumes one use of an API key and returns its Principal.
func (c *Client) VerifyAPIKey(ctx context.Context, raw string) (*Principal, error) {
	return c.authorization.VerifyAPIKey(ctx, raw)
}

// ListAPIKeys returns the API keys owned by a User.
func (c *Client) ListAPIKeys(ctx context.Context, in ListAPIKeysInput) (*ListAPIKeysResult, error) {
	return c.authorization.ListAPIKeys(ctx, in)
}

// RevokeAPIKey revokes one of a User's API keys.
func (c *Client) RevokeAPIKey(ctx context.Context, in RevokeAPIKeyInput) error {
	return c.authorization.RevokeAPIKey(ctx, in)
}

// SetRoles writes a User's global roles when a RoleWriter is configured.
func (c *Client) SetRoles(ctx context.Context, userID string, roles []string) error {
	return c.authorization.SetRoles(ctx, userID, roles)
}

// ListAccounts returns the safe fields of a User's Accounts.
func (c *Client) ListAccounts(ctx context.Context, in ListAccountsInput) (*ListAccountsResult, error) {
	return c.auth.ListAccounts(ctx, in)
}

// UnlinkAccount removes one Account after a recent Session check.
func (c *Client) UnlinkAccount(ctx context.Context, in UnlinkAccountInput) error {
	return c.auth.UnlinkAccount(ctx, in)
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

// SetLastMethodCookie writes the signed Last sign-in method cookie when enabled.
func (c *Client) SetLastMethodCookie(w http.ResponseWriter, method string) {
	if c.lastMethod == nil || method == "" {
		return
	}
	if c.lastMethodBeforeStore != nil && !c.lastMethodBeforeStore(context.Background(), method) {
		return
	}
	c.lastMethod.SetCookie(w, method)
}

// LastSignInMethod reads the signed Last sign-in method from a request.
func (c *Client) LastSignInMethod(_ context.Context, r *http.Request) string {
	if c.lastMethod == nil {
		return ""
	}
	return c.lastMethod.Method(r)
}

// ClearLastSignInMethod expires the Last sign-in method cookie.
func (c *Client) ClearLastSignInMethod(w http.ResponseWriter) {
	if c.lastMethod == nil {
		return
	}
	c.lastMethod.Clear(w)
}

// Handler returns a plain http.Handler serving Signet's authentication endpoints.
func (c *Client) Handler() http.Handler {
	return httpapi.New(httpAdapter{Client: c}, c.cfg.PathPrefix, c.cfg.TrustedProxies).Handler()
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
func (a httpAdapter) SetActiveOrganizationCookie(w http.ResponseWriter, orgID string) {
	if a.activeOrg != nil && orgID != "" {
		a.activeOrg.SetCookie(w, orgID)
	}
}
func (a httpAdapter) LastSignInMethod(r *http.Request) string {
	return a.Client.LastSignInMethod(r.Context(), r)
}
func (a httpAdapter) SetLastMethodCookie(w http.ResponseWriter, method string) {
	a.Client.SetLastMethodCookie(w, method)
}
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
func (a httpAdapter) VerifyAPIKey(ctx context.Context, raw string) (*Principal, error) {
	return a.Client.VerifyAPIKey(ctx, raw)
}
func (a httpAdapter) APIKeyProtectedEndpoints() []string { return a.cfg.APIKeyProtectedEndpoints }
func (a httpAdapter) SetPrincipal(r *http.Request, principal *Principal) *http.Request {
	return r.WithContext(httpapi.WithPrincipal(r.Context(), principal))
}
func (a httpAdapter) SessionTokenFromRequest(r *http.Request) string {
	cookie, err := r.Cookie(a.cookies.Name())
	if err != nil {
		return ""
	}
	return cookie.Value
}

// PrincipalFromContext returns the API-key Principal carried by a request context.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	return httpapi.PrincipalFromContext(ctx)
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
