package signet

import (
	"time"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/mail"
)

// Version is the current Signet version. It remains a development placeholder
// until the first release is tagged.
const Version = "0.0.0-dev"

// Clock supplies the current time so time-dependent behaviour can be tested
// without waiting.
type Clock = core.Clock

// SystemClock is the production Clock, backed by time.Now.
type SystemClock struct{}

// Now returns the current local time.
func (SystemClock) Now() time.Time { return time.Now() }

// Message is the email Signet asks a Mailer to deliver.
type Message = core.Message

// Mailer delivers transactional email such as verification and password
// reset messages.
type Mailer = core.Mailer

// RateLimiter decides whether an action identified by a key may proceed.
type RateLimiter = core.RateLimiter

// Store is the complete persistence contract Signet requires. It composes the
// four narrow contracts so an adapter can be written and tested one concern
// at a time. Lookup misses return ErrNotFound.
type Store = core.Store

// UserStore persists Users.
type UserStore = core.UserStore

// AccountStore persists Accounts.
type AccountStore = core.AccountStore

// SessionStore persists Sessions.
type SessionStore = core.SessionStore

// TokenStore persists Tokens.
type TokenStore = core.TokenStore

// User is the person whose identity Signet manages. A User is the stable
// subject that Accounts and Sessions belong to.
type User = core.User

// Account is a named way a User authenticates: either a credential or a link
// to an external identity provider. A User has one credential Account and may
// have several provider Accounts.
type Account = core.Account

// TokenKind identifies the sensitive flow a Token proves.
type TokenKind = core.TokenKind

const (
	// TokenVerifyEmail proves a request to verify an email address.
	TokenVerifyEmail = core.TokenVerifyEmail
	// TokenResetPassword proves a request to reset a password.
	TokenResetPassword = core.TokenResetPassword
	// TokenOAuthLink proves a request to link an external provider Account.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenOAuthLink = core.TokenOAuthLink
	// TokenRefresh is a rotating credential used to obtain a new Access token.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenRefresh = core.TokenRefresh
	// TokenOAuthState is an OAuth round trip's state, consumed on callback.
	//nolint:gosec // G101: a kind discriminator, not a credential.
	TokenOAuthState = core.TokenOAuthState
)

// Token is a single-use proof for one sensitive flow. Hash holds the stored
// form of the proof; the raw value is never persisted.
type Token = core.Token

// OAuthIdentity is the information a provider reports about a User.
type OAuthIdentity = core.OAuthIdentity

// OAuthProvider is the contract an external identity provider implements.
type OAuthProvider = core.OAuthProvider

// OAuthConfig enables external sign-in providers.
type OAuthConfig = core.OAuthConfig

// TemplateData is the information available to an email template.
type TemplateData = core.TemplateData

// EmailTemplates renders the transactional email Signet sends.
type EmailTemplates = core.EmailTemplates

// DefaultTemplates is the built-in email template set.
var DefaultTemplates = mail.DefaultTemplates
