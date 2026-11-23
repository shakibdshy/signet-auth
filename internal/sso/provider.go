package sso

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/oidc"
)

// oidcProvider is the default SSO OIDC verifier, built from internal/oidc so
// that no production internal package imports the root façade.
type oidcProvider struct {
	client     *http.Client
	connection *core.SSOConnection
	document   *oidc.Document
	keys       *oidc.KeySet
	mapClaims  func(context.Context, *core.SSOClaims) *core.SSOClaims
}

func newOIDCProvider(ctx context.Context, connection *core.SSOConnection, mapper func(context.Context, *core.SSOClaims) *core.SSOClaims) (*oidcProvider, error) {
	client := oidc.SafeHTTP(nil)
	document, err := oidc.Discover(ctx, client, connection.Issuer, "")
	if err != nil {
		return nil, err
	}
	return &oidcProvider{
		client: client, connection: connection, document: document,
		keys: oidc.NewKeySet(client, document.JWKSURI), mapClaims: mapper,
	}, nil
}

func (p *oidcProvider) Name() string { return "sso:" + p.connection.ID }

func (p *oidcProvider) AuthURL(_ string, redirectURI, state, challenge string) string {
	return p.authURL(redirectURI, state, challenge, "")
}

func (p *oidcProvider) AuthURLWithNonce(_ string, redirectURI, state, challenge, nonce string) string {
	return p.authURL(redirectURI, state, challenge, nonce)
}

func (p *oidcProvider) authURL(redirectURI, state, challenge, nonce string) string {
	parsed, err := url.Parse(p.document.AuthorizationEndpoint)
	if err != nil {
		return ""
	}
	query := parsed.Query()
	query.Set("response_type", "code")
	query.Set("client_id", p.connection.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("state", state)
	query.Set("scope", "openid email profile")
	if challenge != "" {
		query.Set("code_challenge", challenge)
		query.Set("code_challenge_method", "S256")
	}
	if nonce != "" {
		query.Set("nonce", nonce)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (p *oidcProvider) Exchange(ctx context.Context, code, verifier, redirectURI string) (*core.OAuthIdentity, error) {
	return p.exchangeWithNonce(ctx, code, verifier, redirectURI, "")
}

func (p *oidcProvider) ExchangeWithNonce(ctx context.Context, code, verifier, redirectURI, nonce string) (*core.OAuthIdentity, error) {
	return p.exchangeWithNonce(ctx, code, verifier, redirectURI, nonce)
}

func (p *oidcProvider) exchangeWithNonce(ctx context.Context, code, verifier, redirectURI, nonce string) (*core.OAuthIdentity, error) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirectURI}, "client_id": {p.connection.ClientID},
	}
	if p.connection.ClientSecret != "" {
		form.Set("client_secret", p.connection.ClientSecret)
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.document.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("sso token exchange failed")
	}
	var result struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.IDToken == "" {
		return nil, core.ErrSSOInvalidAssertion
	}
	claims, err := oidc.Verify(ctx, p.keys, result.IDToken, p.document.Issuer, p.connection.ClientID, p.document.Algorithms)
	if err != nil {
		return nil, core.ErrSSOInvalidAssertion
	}
	if nonce != "" && claims.Nonce != nonce {
		return nil, core.ErrSSOInvalidAssertion
	}
	mapped := &core.SSOClaims{
		Subject: claims.Subject, Email: claims.Email, EmailVerified: claims.EmailVerified,
	}
	if p.mapClaims != nil {
		if result := p.mapClaims(ctx, mapped); result != nil {
			mapped = result
		}
	}
	return &core.OAuthIdentity{
		Provider: p.Name(), ProviderUserID: mapped.Subject,
		Email: mapped.Email, EmailVerified: mapped.EmailVerified,
	}, nil
}

// NewProviderFactory returns a factory using the given claim mapper.
func NewProviderFactory(mapper func(context.Context, *core.SSOClaims) *core.SSOClaims) core.SSOProviderFactory {
	return func(ctx context.Context, connection *core.SSOConnection) (core.OAuthProvider, error) {
		return newOIDCProvider(ctx, connection, mapper)
	}
}

var _ core.OAuthProvider = (*oidcProvider)(nil)
