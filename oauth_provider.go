package signet

import "github.com/shakibdshy/signet/internal/core"

// OAuthIdentity is the verified information a provider returns about a User.
type OAuthIdentity = core.OAuthIdentity

// OAuthProvider is the contract an external identity provider adapter
// implements. It is deliberately small so new providers need no core changes.
type OAuthProvider = core.OAuthProvider

// OAuthConfig enables and configures OAuth sign-in.
type OAuthConfig = core.OAuthConfig
