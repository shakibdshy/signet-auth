// Package core holds Signet's domain types and interfaces. The root signet
// package re-exports them so public import paths and names never change.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
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

// CachedSession is a short-lived copy of a resolved Session.
type CachedSession struct {
	ID                string
	User              *User
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

// SessionCache optionally short-circuits a Session lookup. The Store remains
// authoritative: a cache miss or error falls back to it.
type SessionCache interface {
	Get(context.Context, string) (*CachedSession, error)
	Put(context.Context, string, *CachedSession, time.Duration) error
	Flush(context.Context) error
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
	TokenMagicLink, TokenEmailOTP, TokenTwoFactor,
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
	// TokenMagicLink proves a passwordless magic-link sign-in.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenMagicLink TokenKind = "magic_link"
	// TokenEmailOTP proves a passwordless six-digit email sign-in.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenEmailOTP TokenKind = "email_otp"
	// TokenTwoFactor proves a first factor awaiting a Second factor.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenTwoFactor TokenKind = "two_factor"
	// TokenPasskeyRegistration proves a WebAuthn registration ceremony.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenPasskeyRegistration TokenKind = "passkey_registration"
	// TokenPasskeyAuthentication proves a WebAuthn authentication ceremony.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenPasskeyAuthentication TokenKind = "passkey_authentication"
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

// BreachChecker reports whether a password has appeared in a known breach.
type BreachChecker interface {
	Check(context.Context, string) (bool, error)
}

// CaptchaVerifier verifies a captcha token for a client request.
type CaptchaVerifier interface {
	Verify(context.Context, string, string) error
}

// AuditEvent is a security-relevant action and its outcome.
type AuditEvent struct {
	Name      string
	UserID    string
	SessionID string
	Outcome   string
	Metadata  map[string]string
}

// WebAuthnCredential is the stored public-key record backing a Passkey.
type WebAuthnCredential struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	PublicKey      []byte    `json:"-"`
	AAGUID         string    `json:"aaguid"`
	SignCount      uint32    `json:"sign_count"`
	Transports     []string  `json:"transports,omitempty"`
	BackupEligible bool      `json:"backup_eligible"`
	BackupState    bool      `json:"backup_state"`
	CreatedAt      time.Time `json:"created_at"`
}

// PasskeyInfo is the safe public view of a WebAuthn credential.
type PasskeyInfo struct {
	ID        string    `json:"id"`
	AAGUID    string    `json:"aaguid"`
	SignCount uint32    `json:"sign_count"`
	CreatedAt time.Time `json:"created_at"`
}

// PasskeyStore persists WebAuthn credentials. It is optional.
type PasskeyStore interface {
	CreateCredential(context.Context, *WebAuthnCredential) error
	CredentialsByUser(context.Context, string) ([]*WebAuthnCredential, error)
	CredentialByID(context.Context, string) (*WebAuthnCredential, error)
	UpdateCredential(context.Context, *WebAuthnCredential) error
	DeleteCredential(context.Context, string) error
}

// PasskeyProtocol verifies WebAuthn ceremonies. The default implementation uses
// go-webauthn; applications may supply their own verifier.
type PasskeyProtocol interface {
	BeginRegistration(ctx context.Context, userID, name string, credentials []*WebAuthnCredential) (options []byte, data string, err error)
	FinishRegistration(ctx context.Context, data string, response []byte) (*WebAuthnCredential, error)
	BeginLogin(ctx context.Context) (options []byte, data string, err error)
	FinishLogin(ctx context.Context, data string, response []byte) (userID string, credential *WebAuthnCredential, err error)
}

// PasskeysConfig configures passkeys as a first factor. A nil config disables them.
type PasskeysConfig struct {
	RPID             string
	RPDisplayName    string
	RPOrigins        []string
	Store            PasskeyStore
	Protocol         PasskeyProtocol
	Attestation      bool
	UserVerification bool
}

// PasskeyRegistrationInput starts an enrollment ceremony.
type PasskeyRegistrationInput struct {
	UserID       string `json:"user_id"`
	SessionToken string `json:"-"`
}

// PasskeyCeremonyResult carries browser options and the single-use ceremony token.
type PasskeyCeremonyResult struct {
	Options json.RawMessage `json:"options"`
	Token   string          `json:"token"`
}

// PasskeyFinishInput completes a ceremony with the authenticator response.
type PasskeyFinishInput struct {
	Token        string          `json:"token"`
	Response     json.RawMessage `json:"response"`
	SessionToken string          `json:"-"`
}

// PasskeySignInInput starts a discoverable authentication ceremony.
type PasskeySignInInput struct{}

// PasskeyFinishSignInInput completes a discoverable authentication ceremony.
type PasskeyFinishSignInInput struct {
	Token    string          `json:"token"`
	Response json.RawMessage `json:"response"`
}

// PasskeyListInput selects a User's passkeys.
type PasskeyListInput struct {
	UserID       string `json:"user_id"`
	SessionToken string `json:"-"`
}

// PasskeyListResult contains the safe fields of a User's passkeys.
type PasskeyListResult struct {
	Passkeys []*PasskeyInfo `json:"passkeys"`
}

// PasskeyDeleteInput identifies a passkey to revoke.
type PasskeyDeleteInput struct {
	UserID       string `json:"user_id"`
	CredentialID string `json:"credential_id"`
	SessionToken string `json:"-"`
}

// AuditSink receives Audit events. Implementations own persistence and retention.
type AuditSink interface {
	Record(context.Context, AuditEvent) error
}

// SystemOwnerID scopes API keys with no owning User.
const SystemOwnerID = "signet:system"

// Permission is an exact resource:action authorization string.
type Permission string

// Published permission strings used by Signet's guarded operations.
const (
	PermissionUsersBan         Permission = "users:ban"
	PermissionUsersSetRole     Permission = "users:set-role"
	PermissionUsersImpersonate Permission = "users:impersonate"
	PermissionSessionsRevoke   Permission = "sessions:revoke"
	PermissionAPIKeysCreate    Permission = "api-keys:create"
	PermissionAPIKeysRevoke    Permission = "api-keys:revoke"
	PermissionOrgsCreate       Permission = "organizations:create"
	PermissionOrgsMemberAdd    Permission = "organizations:member-add"
	PermissionOrgsMemberRemove Permission = "organizations:member-remove"
	PermissionOrgsMemberRole   Permission = "organizations:member-role"
)

// RoleStatements maps role names to their granted permissions.
type RoleStatements map[string][]Permission

// Authorizer answers read-only authorization questions.
type Authorizer interface {
	Roles(context.Context, string) []string
	Authorize(ctx context.Context, userID, resource, action string) bool
}

// RoleWriter persists global role assignments.
type RoleWriter interface {
	SetRoles(context.Context, string, []string) error
}

// AuthorizeIn authorizes an action within an Organization.
type AuthorizeIn interface {
	AuthorizeIn(ctx context.Context, userID, orgID, resource, action string) bool
}

// APIKey is a digest-only credential for a non-human client.
type APIKey struct {
	ID          string     `json:"id"`
	OwnerUserID string     `json:"owner_user_id"`
	Name        string     `json:"name"`
	Hash        string     `json:"hash"`
	Prefix      string     `json:"prefix"`
	Roles       []string   `json:"roles"`
	Remaining   int        `json:"remaining"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// APIKeyStore persists digest-only API keys. It is optional. ConsumeAPIKey
// receives a digest, never the raw key. It must atomically look up the key,
// reject expired or exhausted keys and decrement Remaining in one operation.
type APIKeyStore interface {
	Create(context.Context, *APIKey) error
	ConsumeAPIKey(context.Context, string) (*APIKey, error)
	List(context.Context, string) ([]*APIKey, error)
	Revoke(context.Context, string) error
}

// Principal is the identity attached to a verified API key.
type Principal struct {
	OwnerUserID string   `json:"owner_user_id"`
	Roles       []string `json:"roles"`
}

// CreateAPIKeyInput describes a new API key.
type CreateAPIKeyInput struct {
	OwnerUserID  string    `json:"owner_user_id"`
	SessionToken string    `json:"-"`
	Name         string    `json:"name"`
	Roles        []string  `json:"roles"`
	Remaining    int       `json:"remaining"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// CreateAPIKeyResult carries the raw key once and its stored record.
type CreateAPIKeyResult struct {
	Raw string  `json:"raw"`
	Key *APIKey `json:"key"`
}

// ListAPIKeysInput selects the keys owned by a User.
type ListAPIKeysInput struct {
	OwnerUserID  string `json:"owner_user_id"`
	SessionToken string `json:"-"`
}

// ListAPIKeysResult contains a User's API keys.
type ListAPIKeysResult struct {
	Keys []*APIKey `json:"keys"`
}

// RevokeAPIKeyInput identifies a key to revoke and its owner.
type RevokeAPIKeyInput struct {
	OwnerUserID  string `json:"owner_user_id"`
	SessionToken string `json:"-"`
	ID           string `json:"id"`
}

// Organization is a group of Users sharing membership and roles.
type Organization struct {
	ID        string
	OwnerID   string
	Name      string
	CreatedAt time.Time
}

// OrganizationStore persists Organizations and Memberships. It is optional.
type OrganizationStore interface {
	Create(context.Context, *Organization) error
	List(context.Context, string) ([]*Organization, error)
	AddMember(ctx context.Context, orgID, userID, role string) error
	RemoveMember(ctx context.Context, orgID, userID string) error
	MemberRole(ctx context.Context, orgID, userID string) (string, error)
	SetMemberRole(ctx context.Context, orgID, userID, role string) error
	Members(context.Context, string) ([]*MemberInfo, error)
}

// AdminUserStore lists Users for administrative management. It is optional.
type AdminUserStore interface {
	ListUsersForAdmin(context.Context) ([]*User, error)
}

// CreateOrganizationInput describes a new Organization.
type CreateOrganizationInput struct {
	OwnerID      string `json:"owner_id"`
	SessionToken string `json:"-"`
	Name         string `json:"name"`
}

// CreateOrganizationResult carries the created Organization.
type CreateOrganizationResult struct{ Organization *Organization }

// ListOrganizationsInput selects a User's Organizations.
type ListOrganizationsInput struct {
	UserID       string `json:"user_id"`
	SessionToken string `json:"-"`
}

// ListOrganizationsResult contains a User's Organizations.
type ListOrganizationsResult struct{ Organizations []*Organization }

// AddOrganizationMemberInput adds a Member to an Organization.
type AddOrganizationMemberInput struct {
	OrgID        string `json:"org_id"`
	UserID       string `json:"user_id"`
	Role         string `json:"role"`
	ActorID      string `json:"-"`
	SessionToken string `json:"-"`
}

// ListOrganizationMembersInput selects an Organization's Members.
type ListOrganizationMembersInput struct {
	OrgID  string
	UserID string
}

// MemberInfo is a safe representation of a Membership.
type MemberInfo struct {
	UserID string
	Role   string
}

// ListOrganizationMembersResult contains an Organization's Members.
type ListOrganizationMembersResult struct{ Members []*MemberInfo }

// SetActiveOrganizationInput selects an Active organization.
type SetActiveOrganizationInput struct {
	OrgID        string `json:"org_id"`
	UserID       string `json:"-"`
	SessionToken string `json:"-"`
}

// ActiveOrganization is the currently selected Organization.
type ActiveOrganization struct{ ID string }

// AdminListUsersInput selects the User list for an administrator.
type AdminListUsersInput struct {
	ActorID      string `json:"-"`
	SessionToken string `json:"-"`
}

// AdminListUsersResult contains safe User fields.
type AdminListUsersResult struct{ Users []*UserInfo }

// UserInfo is a safe representation of a User.
type UserInfo struct {
	ID       string
	Email    string
	Name     string
	Disabled bool
}

// BanUserInput describes an administrative ban.
type BanUserInput struct {
	ActorID      string
	SessionToken string
	UserID       string
	Reason       string
}

// UnbanUserInput identifies a User to unban.
type UnbanUserInput struct {
	ActorID      string
	SessionToken string
	UserID       string
}

// AdminSetUserRoleInput assigns global roles to a User.
type AdminSetUserRoleInput struct {
	ActorID      string
	SessionToken string
	UserID       string
	Roles        []string
}

// ImpersonateUserInput starts an impersonation Session.
type ImpersonateUserInput struct {
	ActorID      string
	SessionToken string
	UserID       string
}

// ImpersonationResult carries the temporary credentials.
type ImpersonationResult struct {
	Token   string
	AdminID string
}

// StopImpersonatingInput identifies an impersonation to stop.
type StopImpersonatingInput struct {
	Token         string `json:"token"`
	AdminID       string `json:"-"`
	OriginalToken string `json:"-"`
}

// LastSignInMethodConfig controls the optional Last sign-in method cookie.
type LastSignInMethodConfig struct {
	TTL         time.Duration
	CookieName  string
	BeforeStore func(context.Context, string) bool
}

// RateLimiter decides whether an action may proceed.
type RateLimiter interface {
	Allow(context.Context, string) (bool, error)
}

// RateLimitRule overrides the limiter and/or key prefix for one endpoint.
type RateLimitRule struct {
	Limiter   RateLimiter
	KeyPrefix string
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
	Code      string
	ExpiresAt time.Time
}

// EmailTemplates renders Signet's transactional email.
type EmailTemplates interface {
	VerifyEmail(TemplateData) Message
	ResetPassword(TemplateData) Message
	PasswordChanged(TemplateData) Message
}

// MagicLinkTemplates optionally renders the passwordless magic-link email.
// It is a separate interface so existing EmailTemplates implementations keep
// compiling.
type MagicLinkTemplates interface {
	MagicLink(TemplateData) Message
}

// EmailOTPTemplates optionally renders the passwordless OTP email.
type EmailOTPTemplates interface {
	EmailOTP(TemplateData) Message
}

// PasswordlessConfig controls magic-link and email-OTP sign-in.
type PasswordlessConfig struct {
	MagicLinkTTL     time.Duration
	OTPTTL           time.Duration
	AllowSignUp      *bool
	AllowedRedirects []string
}

// RedirectAllowed reports whether redirect is in the allowlist. An empty
// allowlist rejects every redirect; callers supply their own fallback.
func RedirectAllowed(redirect string, allowed []string) bool {
	return RedirectPermitted(redirect, allowed, nil)
}

// RedirectPermitted reports whether redirect matches an exact entry or a
// configured pattern. Exact matches are checked first.
func RedirectPermitted(redirect string, exact, patterns []string) bool {
	for _, candidate := range exact {
		if redirect == candidate {
			return true
		}
	}
	for _, pattern := range patterns {
		if matchRedirectPattern(redirect, pattern) {
			return true
		}
	}
	return false
}

func matchRedirectPattern(redirect, pattern string) bool {
	parsedPattern, err := url.Parse(pattern)
	if err != nil {
		return false
	}
	parsedRedirect, err := url.Parse(redirect)
	if err != nil || parsedRedirect.Scheme != parsedPattern.Scheme {
		return false
	}
	patternHost := parsedPattern.Hostname()
	redirectHost := parsedRedirect.Hostname()
	if !strings.HasPrefix(patternHost, "*.") {
		return redirect == pattern
	}
	suffix := patternHost[1:]
	if strings.Contains(redirectHost, "*") || !strings.HasSuffix(redirectHost, suffix) {
		return false
	}
	base := strings.TrimPrefix(suffix, ".")
	return redirectHost != base && strings.Count(redirectHost, ".") > strings.Count(base, ".")
}

// ValidateRedirectPatterns checks that every pattern is an https URL with a
// wildcard only as the leftmost host label and at least two host labels.
func ValidateRedirectPatterns(patterns []string) error {
	for _, pattern := range patterns {
		parsed, err := url.Parse(pattern)
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" ||
			parsed.Fragment != "" || parsed.Port() != "" || (parsed.Path != "" && parsed.Path != "/") {
			return ErrInvalidRedirectPattern
		}
		host := parsed.Hostname()
		if !strings.HasPrefix(host, "*.") {
			return ErrInvalidRedirectPattern
		}
		labels := strings.Split(strings.TrimPrefix(host, "*."), ".")
		if len(labels) < 2 {
			return ErrInvalidRedirectPattern
		}
		for _, label := range labels {
			if label == "" || strings.Contains(label, "*") {
				return ErrInvalidRedirectPattern
			}
		}
	}
	return nil
}

// JWTConfig enables bearer-token mode.
type JWTConfig struct {
	Key        any
	Keys       []any
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

// AuthURLWithNonce is implemented by Providers that bind an OIDC nonce.
type AuthURLWithNonce interface {
	AuthURLWithNonce(clientID, redirectURI, state, pkceChallenge, nonce string) string
}

// ExchangeWithNonce is implemented by Providers that verify an OIDC nonce.
type ExchangeWithNonce interface {
	ExchangeWithNonce(context.Context, string, string, string, string) (*OAuthIdentity, error)
}

// Config is the complete set of options for a Client.
type Config struct {
	Store                    Store
	Mailer                   Mailer
	PasswordHasher           PasswordHasher
	RateLimiter              RateLimiter
	RateLimitRules           map[string]RateLimitRule
	TrustedProxies           []netip.Prefix
	Clock                    Clock
	Logger                   *slog.Logger
	OnSignUp                 func(context.Context, *User)
	OnSignIn                 func(context.Context, *User)
	Cookie                   CookieConfig
	Session                  SessionConfig
	SessionCache             SessionCache
	Password                 PasswordConfig
	Username                 *UsernameConfig
	TOTPStore                TOTPStore
	TOTPKey                  []byte
	TOTP                     *TOTPConfig
	Accounts                 *AccountConfig
	PathPrefix               string
	InsecureAllowHTTPCookies bool
	InsecureDisableCSRF      bool
	JWT                      *JWTConfig
	RequireVerifiedEmail     *bool
	SendVerificationOnSignUp *bool
	AppURL                   string
	Templates                EmailTemplates
	OAuth                    *OAuthConfig
	Passwordless             *PasswordlessConfig
	AllowedRedirectPatterns  []string
	BreachChecker            BreachChecker
	CaptchaVerifier          CaptchaVerifier
	CaptchaEndpoints         []string
	AuditSink                AuditSink
	Passkeys                 *PasskeysConfig
	Authorizer               Authorizer
	AuthorizeIn              AuthorizeIn
	RoleWriter               RoleWriter
	APIKeyStore              APIKeyStore
	APIKeyProtectedEndpoints []string
	OrganizationStore        OrganizationStore
	AdminUserStore           AdminUserStore
	LastSignInMethod         *LastSignInMethodConfig
	CSRFKey                  []byte
	CSRFKeys                 [][]byte
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
	// CacheTTL enables the optional Session cache. Zero disables it.
	CacheTTL time.Duration
	// FreshAge is the window since authentication for freshness checks.
	// Zero disables freshness enforcement.
	FreshAge time.Duration
}

// UsernameConfig controls Username normalization and validation.
type UsernameConfig struct {
	MinLength int
	MaxLength int
	Reserved  []string
	Normalize func(string) string
}

// AccountConfig controls account-management safeguards.
type AccountConfig struct {
	FreshWindow time.Duration
}

// TOTPConfig controls TOTP code generation and verification.
type TOTPConfig struct {
	Digits int
	Period int
	Window int
	Issuer string
}

// TOTPState is the persisted state of a User's Second factor enrollment.
type TOTPState struct {
	Secret      string
	BackupCodes []string
	Verified    bool
}

// TOTPStore persists TOTP enrollment state. It is optional; without one,
// Second factor is unavailable.
type TOTPStore interface {
	Get(context.Context, string) (*TOTPState, error)
	Put(context.Context, string, *TOTPState) error
	Delete(context.Context, string) error
}

// PasswordConfig bounds accepted password lengths.
type PasswordConfig struct {
	MinLength int
	MaxLength int
}

// SignUpInput is the input to a sign-up.
type SignUpInput struct {
	Email           string `json:"email"`
	CaptchaToken    string `json:"-"`
	CaptchaRemoteIP string `json:"-"`
	Password        string `json:"password"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	RateLimitKey    string `json:"-"`
}

// SignUpResult is the outcome of a successful sign-up.
type SignUpResult struct{ User *User }

// SignInInput is the input to a sign-in.
type SignInInput struct {
	Email           string `json:"email"`
	CaptchaToken    string `json:"-"`
	CaptchaRemoteIP string `json:"-"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	RateLimitKey    string `json:"-"`
}

// SignInResult is the outcome of a successful sign-in.
type SignInResult struct {
	User         *User
	SessionToken string
	// TwoFactorChallenge is returned instead of a Session when a Second factor is required.
	TwoFactorChallenge string `json:"two_factor_challenge,omitempty"`
	LastSignInMethod   string `json:"last_sign_in_method,omitempty"`
	// CallbackURL is the allowlisted callback embedded in a magic-link proof.
	// It is transport-only and never serialised.
	CallbackURL string `json:"-"`
}

// AccountInfo is the safe representation of an Account.
type AccountInfo struct {
	ID             string    `json:"id"`
	Provider       string    `json:"provider"`
	ProviderUserID string    `json:"provider_user_id"`
	Email          string    `json:"email"`
	EmailVerified  bool      `json:"email_verified"`
	CreatedAt      time.Time `json:"created_at"`
}

// ListAccountsInput selects the User whose Accounts should be listed.
type ListAccountsInput struct{ UserID string }

// ListAccountsResult contains the safe fields of a User's Accounts.
type ListAccountsResult struct{ Accounts []*AccountInfo }

// UnlinkAccountInput identifies one Account to unlink and the Session proving
// the request is recent.
type UnlinkAccountInput struct {
	UserID       string `json:"-"`
	AccountID    string `json:"account_id"`
	SessionToken string `json:"-"`
	RateLimitKey string `json:"-"`
}

// EnableTwoFactorInput enables Second factor enrollment.
type EnableTwoFactorInput struct {
	UserID       string `json:"-"`
	Password     string `json:"password"`
	RateLimitKey string `json:"-"`
}

// EnableTwoFactorResult carries a provisioning URI and the initial Backup codes.
type EnableTwoFactorResult struct {
	TOTPURI     string   `json:"totp_uri"`
	Challenge   string   `json:"challenge"`
	BackupCodes []string `json:"backup_codes"`
}

// VerifyTwoFactorInput exchanges a Two-factor challenge for a Session.
type VerifyTwoFactorInput struct {
	Challenge    string `json:"challenge"`
	Code         string `json:"code"`
	RateLimitKey string `json:"-"`
}

// DisableTwoFactorInput removes a User's Second factor enrollment.
type DisableTwoFactorInput struct {
	UserID       string `json:"-"`
	Password     string `json:"password"`
	RateLimitKey string `json:"-"`
}

// RegenerateBackupCodesInput replaces all Backup codes.
type RegenerateBackupCodesInput struct {
	UserID       string `json:"-"`
	SessionToken string `json:"-"`
	Password     string `json:"password"`
	RateLimitKey string `json:"-"`
}

// RegenerateBackupCodesResult carries a fresh set of Backup codes.
type RegenerateBackupCodesResult struct {
	BackupCodes []string `json:"backup_codes"`
}

// SendMagicLinkInput requests a magic-link sign-in email.
type SendMagicLinkInput struct {
	Email        string `json:"email"`
	Name         string `json:"name"`
	CallbackURL  string `json:"callback_url"`
	RateLimitKey string `json:"-"`
}

// VerifyMagicLinkInput carries the proof from a magic-link email and,
// optionally, a callback URL that must match the one embedded in the proof.
type VerifyMagicLinkInput struct {
	Token        string `json:"token"`
	CallbackURL  string `json:"callback_url"`
	RateLimitKey string `json:"-"`
}

// SendEmailOTPInput requests a six-digit sign-in code by email.
type SendEmailOTPInput struct {
	Email        string `json:"email"`
	Name         string `json:"name"`
	RateLimitKey string `json:"-"`
}

// VerifyEmailOTPInput carries a sign-in code and the address it was sent to.
type VerifyEmailOTPInput struct {
	Email        string `json:"email"`
	Code         string `json:"code"`
	RateLimitKey string `json:"-"`
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
	Email           string `json:"email"`
	CaptchaToken    string `json:"-"`
	CaptchaRemoteIP string `json:"-"`
	RateLimitKey    string `json:"-"`
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
	SessionToken    string `json:"-"`
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
	Challenge    string `json:"challenge"`
	Code         string `json:"code"`
	RateLimitKey string `json:"-"`
}

// TokenPair is the result of a token exchange.
type TokenPair struct {
	AccessToken        string `json:"access_token"`
	RefreshToken       string `json:"refresh_token"`
	ExpiresIn          int64  `json:"expires_in"`
	TwoFactorChallenge string `json:"two_factor_challenge,omitempty"`
	LastSignInMethod   string `json:"last_sign_in_method,omitempty"`
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
	User             *User
	SessionToken     string
	LastSignInMethod string
	LinkToken        string
	Redirect         string
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
	// ErrTokenConsumed reports a Token that was already used. It wraps
	// ErrTokenInvalid so existing callers keep treating replay as invalid.
	ErrTokenConsumed = fmt.Errorf("%w: already consumed", ErrTokenInvalid)
	// ErrInvalidOTP reports a missing, malformed, unknown or expired email OTP.
	ErrInvalidOTP = errors.New("signet: invalid or expired code")
	// ErrOTPAlreadyUsed reports an email OTP that was already consumed.
	ErrOTPAlreadyUsed = errors.New("signet: code already used")
	// ErrInvalidMagicLink reports a missing, malformed, unknown or expired magic link.
	ErrInvalidMagicLink = errors.New("signet: invalid or expired magic link")
	// ErrMagicLinkAlreadyUsed reports a magic link that was already consumed.
	ErrMagicLinkAlreadyUsed = errors.New("signet: magic link already used")
	// ErrInvalidRateLimitRule reports a rule for an unknown endpoint name.
	ErrInvalidRateLimitRule = errors.New("signet: invalid rate limit rule")
	// ErrSessionNotFresh reports a Session outside the freshness window.
	ErrSessionNotFresh = errors.New("signet: session not fresh")
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
	// ErrInvalidKeyRing reports an empty, mixed or duplicate key ring.
	ErrInvalidKeyRing = errors.New("signet: invalid key ring")
	// ErrInvalidRedirectPattern reports a malformed redirect pattern.
	ErrInvalidRedirectPattern = errors.New("signet: invalid redirect pattern")
	// ErrInvalidUsername reports a malformed or reserved Username.
	ErrInvalidUsername = errors.New("signet: invalid username")
	// ErrUsernameTaken reports a Username already owned by another User.
	ErrUsernameTaken = errors.New("signet: username already taken")
	// ErrLastAccount reports an unlink that would leave a User with no Account.
	ErrLastAccount = errors.New("signet: cannot unlink the last account")
	// ErrTOTPNotEnabled reports a Second factor operation for an unenrolled User.
	ErrTOTPNotEnabled = errors.New("signet: second factor is not enabled")
	// ErrTOTPInvalid reports an invalid TOTP code or Backup code.
	ErrTOTPInvalid = errors.New("signet: invalid second factor code")
	// ErrTwoFactorRequired reports a sign-in that needs a Second factor.
	ErrTwoFactorRequired = errors.New("signet: second factor required")
	// ErrTOTPNotConfigured reports a Second factor operation without a configured store or key.
	ErrTOTPNotConfigured = errors.New("signet: second factor is not configured")
	// ErrPasswordCompromised reports a password found in a known breach.
	ErrPasswordCompromised = errors.New("signet: password has been compromised")
	// ErrCaptchaRequired reports a missing captcha token.
	ErrCaptchaRequired = errors.New("signet: captcha token required")
	// ErrCaptchaInvalid reports a rejected captcha token.
	ErrCaptchaInvalid = errors.New("signet: captcha verification failed")
	// ErrCaptchaUnavailable reports a captcha provider outage.
	ErrCaptchaUnavailable = errors.New("signet: captcha provider unavailable")
	// ErrInvalidCaptchaEndpoint reports an unsupported captcha endpoint name.
	ErrInvalidCaptchaEndpoint = errors.New("signet: invalid captcha endpoint")
	// ErrRefreshReuse reports replay of a consumed Refresh token.
	ErrRefreshReuse = errors.New("signet: refresh token reuse detected")
	// ErrInvalidOAuthConfig reports invalid OAuth configuration.
	ErrInvalidOAuthConfig = errors.New("signet: invalid oauth configuration")
	// ErrOAuthProviderConflict reports duplicate or reserved provider IDs.
	ErrOAuthProviderConflict = errors.New("signet: oauth provider id conflict")
	// ErrInvalidPasswordlessConfig reports invalid passwordless configuration.
	ErrInvalidPasswordlessConfig = errors.New("signet: invalid passwordless configuration")
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
	// ErrInvalidPasskeysConfig reports an invalid passkeys configuration.
	ErrInvalidPasskeysConfig = errors.New("signet: invalid passkeys configuration")
	// ErrForbidden reports an authorization denial.
	ErrForbidden = errors.New("signet: forbidden")
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
