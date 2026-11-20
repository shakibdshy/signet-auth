// Package github provides a Signet OAuthProvider adapter for GitHub.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/shakibdshy/signet"
	"golang.org/x/oauth2"
)

const (
	defaultAuthURL     = "https://github.com/login/oauth/authorize"
	defaultExchangeURL = "https://github.com/login/oauth/access_token"
	defaultUserURL     = "https://api.github.com/user"
	defaultEmailsURL   = "https://api.github.com/user/emails"
)

// Provider implements signet.OAuthProvider for GitHub. Endpoint fields allow
// overriding the defaults in tests; leave them empty in production.
type Provider struct {
	ClientID     string
	ClientSecret string
	AuthEndpoint string
	TokenURL     string
	UserInfoURL  string
	EmailsURL    string
}

// Name returns the provider identifier used in configuration and Accounts.
func (p Provider) Name() string { return "github" }

func (p Provider) config(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  redirectURI,
		Scopes:       []string{"user:email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  firstNonEmpty(p.AuthEndpoint, defaultAuthURL),
			TokenURL: firstNonEmpty(p.TokenURL, defaultExchangeURL),
		},
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// AuthURL builds the GitHub authorization URL with the PKCE challenge.
func (p Provider) AuthURL(clientID, redirectURI, state, challenge string) string {
	cfg := p.config(redirectURI)
	if clientID != "" {
		cfg.ClientID = clientID
	}
	return cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
}

// Exchange redeems the code and reads the identity plus GitHub's verified
// primary email from the dedicated email endpoint.
func (p Provider) Exchange(ctx context.Context, code, verifier, redirectURI string) (*signet.OAuthIdentity, error) {
	token, err := p.config(redirectURI).Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("signet/oauth/github: exchange: %w", err)
	}
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	resp, err := client.Get(firstNonEmpty(p.UserInfoURL, defaultUserURL))
	if err != nil {
		return nil, fmt.Errorf("signet/oauth/github: user: %w", err)
	}
	var user struct {
		ID int64 `json:"id"`
	}
	err = func() error {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("signet/oauth/github: user status %d", resp.StatusCode)
		}
		return json.NewDecoder(resp.Body).Decode(&user)
	}()
	if err != nil {
		return nil, err
	}
	emailsResp, err := client.Get(firstNonEmpty(p.EmailsURL, defaultEmailsURL))
	if err != nil {
		return nil, fmt.Errorf("signet/oauth/github: emails: %w", err)
	}
	defer func() { _ = emailsResp.Body.Close() }()
	if emailsResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signet/oauth/github: emails status %d", emailsResp.StatusCode)
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(emailsResp.Body).Decode(&emails); err != nil {
		return nil, fmt.Errorf("signet/oauth/github: decode emails: %w", err)
	}
	identity := &signet.OAuthIdentity{
		Provider: "github", ProviderUserID: strconv.FormatInt(user.ID, 10),
	}
	for _, email := range emails {
		if email.Primary {
			identity.Email = email.Email
			identity.EmailVerified = email.Verified
			break
		}
	}
	return identity, nil
}
