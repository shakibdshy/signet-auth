// Package core holds Signet's domain types and interfaces. The root signet
// package re-exports them so public import paths and names never change.
package core

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// User is the person whose identity Signet manages.
type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Name          string    `json:"name"`
	Disabled      bool      `json:"disabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Account is a named way a User authenticates.
type Account struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	Provider       string    `json:"provider"`
	ProviderUserID string    `json:"provider_user_id"`
	Email          string    `json:"email"`
	EmailVerified  bool      `json:"email_verified"`
	PasswordHash   string    `json:"password_hash"`
	CreatedAt      time.Time `json:"created_at"`
}

// Session is one authenticated visit by a User.
type Session struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	TokenHash         string     `json:"token_hash"`
	CreatedAt         time.Time  `json:"created_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	IdleExpiresAt     time.Time  `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time  `json:"absolute_expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
}

// AllTokenKinds is the canonical list of single-use proof kinds. Security
// checks that must revoke every kind iterate this list so a new kind cannot be
// silently omitted.
var AllTokenKinds = []TokenKind{
	TokenVerifyEmail, TokenChangeEmail, TokenDeleteUser, TokenResetPassword, TokenOAuthLink, TokenRefresh, TokenOAuthState,
}

// TokenKind identifies the sensitive flow a Token proves.
type TokenKind string

const (
	// TokenVerifyEmail proves a request to verify an email address.
	TokenVerifyEmail TokenKind = "verify_email"
	// TokenDeleteUser proves a request to delete an Account.
	TokenDeleteUser TokenKind = "delete_user"
	// TokenChangeEmail proves a request to change a User's email address.
	TokenChangeEmail TokenKind = "change_email"
	// TokenResetPassword proves a request to reset a password.
	TokenResetPassword TokenKind = "reset_password"
	// TokenOAuthLink proves a request to link an external provider Account.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenOAuthLink TokenKind = "oauth_link"
	// TokenRefresh is a rotating credential used to obtain a new Access token.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenRefresh TokenKind = "refresh"
	// TokenOAuthState is an OAuth round trip's state, consumed on callback.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenOAuthState TokenKind = "oauth_state"
)

// Token is a single-use proof for one sensitive flow.
type Token struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Kind      TokenKind  `json:"kind"`
	Hash      string     `json:"hash"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Store is the complete persistence contract Signet requires.
type Store interface {
	UserStore
	AccountStore
	SessionStore
	TokenStore
}

// UserStore persists Users.
type UserStore interface {
	CreateUser(context.Context, *User) error
	UserByID(context.Context, string) (*User, error)
	UserByEmail(context.Context, string) (*User, error)
	UpdateUser(context.Context, *User) error
	DeleteUser(context.Context, string) error
}

// AccountStore persists Accounts.
type AccountStore interface {
	CreateAccount(context.Context, *Account) error
	AccountsForUser(context.Context, string) ([]*Account, error)
	AccountByProvider(context.Context, string, string) (*Account, error)
	UpdateAccount(context.Context, *Account) error
	DeleteAccount(context.Context, string) error
}

// SessionStore persists Sessions.
type SessionStore interface {
	CreateSession(context.Context, *Session) error
	SessionByHash(context.Context, string) (*Session, error)
	TouchSession(context.Context, string, time.Time) error
	DeleteSession(context.Context, string) error
	DeleteSessionsForUser(context.Context, string) error
	ListSessionsForUser(context.Context, string) ([]*Session, error)
}

// TokenStore persists Tokens.
type TokenStore interface {
	CreateToken(context.Context, *Token) error
	ConsumeToken(context.Context, TokenKind, string) (*Token, error)
	TokenByHash(context.Context, TokenKind, string) (*Token, error)
	DeleteTokensForUser(context.Context, string, TokenKind) error
}

// Message is an email Signet asks a Mailer to deliver.
type Message struct {
	To       string
	Subject  string
	TextBody string
	HTMLBody string
}

// Mailer delivers transactional email.
type Mailer interface {
	Send(context.Context, Message) error
}

// PasswordHasher stores and verifies password verifiers.
type PasswordHasher interface {
	Hash(context.Context, string) (string, error)
	Verify(context.Context, string, string) (bool, error)
	NeedsRehash(string) bool
}

// RateLimiter decides whether an action may proceed.
type RateLimiter interface {
	Allow(context.Context, string) (bool, error)
}

// Clock supplies the current time.
type Clock interface {
	Now() time.Time
}

// TemplateData is the information available to an email template.
type TemplateData struct {
	Email     string
	Name      string
	URL       string
	ExpiresAt time.Time
}

// EmailTemplates renders Signet's transactional email.
type EmailTemplates interface {
	VerifyEmail(TemplateData) Message
	ResetPassword(TemplateData) Message
	PasswordChanged(TemplateData) Message
}

// JWTConfig enables bearer-token mode.
type JWTConfig struct {
	Key        any
	Algorithm  string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	Issuer     string
}

// OAuthConfig enables external sign-in providers.
type OAuthConfig struct {
	Providers        []OAuthProvider
	RedirectBaseURL  string
	AllowedRedirects []string
	StateKey         []byte
}

// OAuthIdentity is the information a provider returns about a User.
type OAuthIdentity struct {
	Provider       string
	ProviderUserID string
	Email          string
	EmailVerified  bool
}

// OAuthProvider is the contract an external identity provider implements.
type OAuthProvider interface {
	Name() string
	AuthURL(clientID, redirectURI, state, pkceChallenge string) string
	Exchange(context.Context, string, string, string) (*OAuthIdentity, error)
}

// Config is the complete set of options for a Client.
type Config struct {
	Store                    Store
	Mailer                   Mailer
	PasswordHasher           PasswordHasher
	RateLimiter              RateLimiter
	Clock                    Clock
	Logger                   *slog.Logger
	OnSignUp                 func(context.Context, *User)
	OnSignIn                 func(context.Context, *User)
	Cookie                   CookieConfig
	Session                  SessionConfig
	Password                 PasswordConfig
	PathPrefix               string
	InsecureAllowHTTPCookies bool
	InsecureDisableCSRF      bool
	JWT                      *JWTConfig
	RequireVerifiedEmail     *bool
	SendVerificationOnSignUp *bool
	AppURL                   string
	Templates                EmailTemplates
	OAuth                    *OAuthConfig
	CSRFKey                  []byte
	JWTOnly                  bool
}

// CookieConfig controls the session cookie.
type CookieConfig struct {
	Name     string
	Domain   string
	Path     string
	SameSite http.SameSite
	Secure   bool
	//nolint:revive // Matches the http.Cookie field name consumers already know.
	HttpOnly bool
}

// SessionConfig controls Session lifetimes.
type SessionConfig struct {
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
}

// PasswordConfig bounds accepted password lengths.
type PasswordConfig struct {
	MinLength int
	MaxLength int
}

// SignUpInput is the input to a sign-up.
type SignUpInput struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	Name         string `json:"name"`
	RateLimitKey string `json:"-"`
}

// SignUpResult is the outcome of a successful sign-up.
type SignUpResult struct{ User *User }

// SignInInput is the input to a sign-in.
type SignInInput struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	RateLimitKey string `json:"-"`
}

// SignInResult is the outcome of a successful sign-in.
type SignInResult struct {
	User         *User
	SessionToken string
}

// SignOutInput is the input to a sign-out.
type SignOutInput struct {
	SessionToken string `json:"session_token"`
}

// SendVerificationInput requests a verification email.
type SendVerificationInput struct {
	Email        string `json:"email"`
	RateLimitKey string `json:"-"`
}

// VerifyEmailInput carries a verification Token.
type VerifyEmailInput struct {
	Token        string `json:"token"`
	RateLimitKey string `json:"-"`
}

// SendPasswordResetInput requests a password reset email.
type SendPasswordResetInput struct {
	Email        string `json:"email"`
	RateLimitKey string `json:"-"`
}

// ResetPasswordInput carries a reset Token and new password.
type ResetPasswordInput struct {
	Token        string `json:"token"`
	NewPassword  string `json:"new_password"`
	RateLimitKey string `json:"-"`
}

// ChangePasswordInput carries the authenticated User ID and the old and new passwords.
type ChangePasswordInput struct {
	UserID          string `json:"-"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	RateLimitKey    string `json:"-"`
}

// RequestDeleteUserInput identifies the User requesting account deletion.
type RequestDeleteUserInput struct {
	UserID       string `json:"-"`
	RateLimitKey string `json:"-"`
}

// ConfirmDeleteUserInput carries the single-use proof from the deletion email.
type ConfirmDeleteUserInput struct {
	Token        string `json:"token"`
	RateLimitKey string `json:"-"`
}

// DeleteUserTemplates renders the message that confirms account deletion.
type DeleteUserTemplates interface {
	DeleteUser(TemplateData) Message
}

// ChangeEmailInput carries the new address and the current password for an
// authenticated User.
type ChangeEmailInput struct {
	UserID          string `json:"-"`
	NewEmail        string `json:"new_email"`
	CurrentPassword string `json:"current_password"`
	RateLimitKey    string `json:"-"`
}

// VerifyEmailChangeInput carries the single-use proof from the emailed link.
type VerifyEmailChangeInput struct {
	Token        string `json:"token"`
	RateLimitKey string `json:"-"`
}

// EmailChangeTemplates renders the message that confirms an email change.
// It is optional: applications may keep their existing EmailTemplates
// implementation and Signet will use a built-in default.
type EmailChangeTemplates interface {
	ChangeEmail(TemplateData) Message
}

// TokenInput selects a token exchange.
type TokenInput struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	RefreshToken string `json:"refresh_token"`
	RateLimitKey string `json:"-"`
}

// TokenPair is the result of a token exchange.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// OAuthStartInput selects a provider and redirect target.
type OAuthStartInput struct {
	Provider     string `json:"provider"`
	Redirect     string `json:"redirect"`
	RateLimitKey string `json:"-"`
}

// OAuthStartResult carries the provider authorization URL.
type OAuthStartResult struct {
	URL string `json:"url"`
}

// OAuthCallbackInput carries the provider code and state.
type OAuthCallbackInput struct {
	Code         string `json:"code"`
	State        string `json:"state"`
	RateLimitKey string `json:"-"`
}

// OAuthCallbackResult carries a signed-in User or an explicit link token.
type OAuthCallbackResult struct {
	User         *User
	SessionToken string
	LinkToken    string
	Redirect     string
}

// LinkOAuthAccountInput carries the one-time link token and User ID.
type LinkOAuthAccountInput struct {
	UserID    string `json:"user_id"`
	LinkToken string `json:"link_token"`
}

var (
	// ErrNotFound reports a missing entity.
	ErrNotFound = errors.New("signet: not found")
	// ErrInvalidCredentials reports a failed sign-in.
	ErrInvalidCredentials = errors.New("signet: invalid credentials")
	// ErrEmailNotVerified reports an unverified email.
	ErrEmailNotVerified = errors.New("signet: email not verified")
	// ErrRateLimited reports a rate limit.
	ErrRateLimited = errors.New("signet: rate limited")
	// ErrTokenExpired reports an expired Token.
	ErrTokenExpired = errors.New("signet: token expired")
	// ErrTokenInvalid reports an invalid Token.
	ErrTokenInvalid = errors.New("signet: token invalid")
	// ErrMissingStore reports a missing Store.
	ErrMissingStore = errors.New("signet: Config.Store is required")
	// ErrMissingMailer reports a missing Mailer.
	ErrMissingMailer = errors.New("signet: Config.Mailer is required")
	// ErrMissingHasher reports a missing PasswordHasher.
	ErrMissingHasher = errors.New("signet: Config.PasswordHasher is required")
	// ErrMissingRateLimiter reports a missing RateLimiter.
	ErrMissingRateLimiter = errors.New("signet: Config.RateLimiter is required")
	// ErrInsecureConfig reports an insecure configuration.
	ErrInsecureConfig = errors.New("signet: insecure configuration")
	// ErrInvalidEmail reports an invalid email.
	ErrInvalidEmail = errors.New("signet: invalid email")
	// ErrPasswordTooShort reports a short password.
	ErrPasswordTooShort = errors.New("signet: password too short")
	// ErrPasswordTooLong reports a long password.
	ErrPasswordTooLong = errors.New("signet: password too long")
	// ErrEmailAlreadyExists reports a duplicate email.
	ErrEmailAlreadyExists = errors.New("signet: email already exists")
	// ErrJWTDisabled reports disabled JWT mode.
	ErrJWTDisabled = errors.New("signet: jwt mode is disabled")
	// ErrInvalidJWTAlgorithm reports an invalid JWT algorithm.
	ErrInvalidJWTAlgorithm = errors.New("signet: invalid jwt algorithm")
	// ErrInvalidJWTKey reports an invalid JWT key.
	ErrInvalidJWTKey = errors.New("signet: invalid jwt signing key")
	// ErrRefreshReuse reports replay of a consumed Refresh token.
	ErrRefreshReuse = errors.New("signet: refresh token reuse detected")
	// ErrInvalidOAuthConfig reports invalid OAuth configuration.
	ErrInvalidOAuthConfig = errors.New("signet: invalid oauth configuration")
	// ErrOAuthDisabled reports disabled OAuth.
	ErrOAuthDisabled = errors.New("signet: oauth is disabled")
	// ErrOAuthProviderNotFound reports an unknown provider.
	ErrOAuthProviderNotFound = errors.New("signet: oauth provider not found")
	// ErrOAuthInvalidState reports invalid OAuth state.
	ErrOAuthInvalidState = errors.New("signet: invalid oauth state")
	// ErrOAuthRedirectNotAllowed reports a disallowed redirect.
	ErrOAuthRedirectNotAllowed = errors.New("signet: oauth redirect not allowed")
	// ErrOAuthEmailNotVerified reports an unverified provider email.
	ErrOAuthEmailNotVerified = errors.New("signet: oauth email not verified")
	// ErrOAuthAccountConflict reports a provider Account owned by another User.
	ErrOAuthAccountConflict = errors.New("signet: oauth account conflict")
	// ErrInvalidCSRFConfig reports an invalid CSRF key.
	ErrInvalidCSRFConfig = errors.New("signet: invalid csrf configuration")
)

// ListSessionsInput selects the User whose Sessions should be listed.
type ListSessionsInput struct{ UserID string }

// ListSessionsResult contains safe Session fields.
type ListSessionsResult struct{ Sessions []*SessionInfo }

// RevokeSessionInput identifies one Session.
type RevokeSessionInput struct{ SessionID string }

// RevokeAllSessionsInput identifies the User whose Sessions to revoke.
type RevokeAllSessionsInput struct{ UserID string }

// SessionInfo is the safe representation of a Session.
type SessionInfo struct {
	ID                string     `json:"id"`
	CreatedAt         time.Time  `json:"created_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	IdleExpiresAt     time.Time  `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time  `json:"absolute_expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
}
