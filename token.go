package signet

import "github.com/shakibdshy/signet/internal/core"

// TokenKind identifies the sensitive flow a Token proves.
type TokenKind = core.TokenKind

const (
	// TokenVerifyEmail is re-exported from core.
	TokenVerifyEmail = core.TokenVerifyEmail
	// TokenResetPassword is re-exported from core.
	TokenResetPassword = core.TokenResetPassword
	// TokenOAuthLink proves a request to link an external provider Account.
	// TokenOAuthLink is re-exported from core.
	TokenOAuthLink = core.TokenOAuthLink
	// TokenRefresh is a rotating credential used to obtain a new Access token.
	// TokenRefresh is re-exported from core.
	TokenRefresh = core.TokenRefresh
	// TokenOAuthState is an OAuth round trip's state, consumed on callback.
	// TokenOAuthState is re-exported from core.
	TokenOAuthState = core.TokenOAuthState
)

// Token is a single-use proof for one sensitive flow. Hash holds the stored
// form of the proof; the raw value is never persisted.
type Token = core.Token
