package signet

import "github.com/shakibdshy/signet/internal/core"

// OAuthIdentity is the information a provider reports about a User.
type OAuthIdentity = core.OAuthIdentity

// OAuthProvider is the contract an external identity provider implements.
type OAuthProvider = core.OAuthProvider

// OAuthConfig enables external sign-in providers.
type OAuthConfig = core.OAuthConfig
