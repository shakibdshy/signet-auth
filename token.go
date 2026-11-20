package signet

import "github.com/shakibdshy/signet/internal/core"

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
