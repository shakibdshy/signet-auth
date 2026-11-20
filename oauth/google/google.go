// Package google provides a Signet OAuthProvider adapter for Google.
package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/shakibdshy/signet"
	"golang.org/x/oauth2"
)

const (
	defaultAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	defaultExchangeURL = "https://oauth2.googleapis.com/token"
	defaultUserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
)

// Provider implements signet.OAuthProvider for Google. Endpoint fields allow
// overriding the defaults in tests; leave them empty in production.
type Provider struct {
	ClientID     string
	ClientSecret string
	AuthEndpoint string
	TokenURL     string
	UserInfoURL  string
}

// Name returns the provider identifier used in configuration and Accounts.
func (p Provider) Name() string { return "google" }

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (p Provider) config(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  redirectURI,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  firstNonEmpty(p.AuthEndpoint, defaultAuthURL),
			TokenURL: firstNonEmpty(p.TokenURL, defaultExchangeURL),
		},
	}
}

// AuthURL builds the Google authorization URL with the PKCE challenge.
func (p Provider) AuthURL(clientID, redirectURI, state, challenge string) string {
	cfg := p.config(redirectURI)
	if clientID != "" {
		cfg.ClientID = clientID
	}
	return cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
}

// Exchange redeems the code and reads the verified Google identity.
func (p Provider) Exchange(ctx context.Context, code, verifier, redirectURI string) (*signet.OAuthIdentity, error) {
	token, err := p.config(redirectURI).Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("signet/oauth/google: exchange: %w", err)
	}
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	resp, err := client.Get(firstNonEmpty(p.UserInfoURL, defaultUserInfoURL))
	if err != nil {
		return nil, fmt.Errorf("signet/oauth/google: userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signet/oauth/google: userinfo status %d", resp.StatusCode)
	}
	var info struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("signet/oauth/google: decode userinfo: %w", err)
	}
	return &signet.OAuthIdentity{
		Provider: "google", ProviderUserID: info.Sub,
		Email: info.Email, EmailVerified: info.EmailVerified,
	}, nil
}
