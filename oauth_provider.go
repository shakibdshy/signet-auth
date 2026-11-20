package signet

import "context"

// OAuthIdentity is the verified information a provider returns about a User.
type OAuthIdentity struct {
	Provider       string
	ProviderUserID string
	Email          string
	EmailVerified  bool
}

// OAuthProvider is the contract an external identity provider adapter
// implements. It is deliberately small so new providers need no core changes.
type OAuthProvider interface {
	// Name is the provider's identifier in configuration and Account records.
	Name() string
	// AuthURL builds the provider's authorization URL for a request.
	AuthURL(clientID, redirectURI, state, pkceChallenge string) string
	// Exchange redeems an authorization code using its PKCE verifier.
	Exchange(context.Context, string, string, string) (*OAuthIdentity, error)
}

// OAuthConfig enables and configures OAuth sign-in.
type OAuthConfig struct {
	Providers        []OAuthProvider
	RedirectBaseURL  string
	AllowedRedirects []string
	StateKey         []byte
}
