package signet

import "time"

// TokenKind identifies the sensitive flow a Token proves.
type TokenKind string

const (
	// TokenVerifyEmail proves a request to verify an email address.
	TokenVerifyEmail TokenKind = "verify_email"
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

// Token is a single-use proof for one sensitive flow. Hash holds the stored
// form of the proof; the raw value is never persisted.
type Token struct {
	ID        string
	UserID    string
	Kind      TokenKind
	Hash      string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}
