// Package oidc provides a generic OAuth/OIDC provider adapter for Signet.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/oidc"
)

var allowedAlgorithms = []string{"RS256", "PS256", "ES256", "ES384", "ES512", "EdDSA"}

// Config describes a generic OIDC Provider.
type Config struct {
	ProviderID        string
	ClientID          string
	ClientSecret      string
	Issuer            string
	DiscoveryURL      string
	AuthorizationURL  string
	TokenURL          string
	UserInfoURL       string
	JWKSURI           string
	Scopes            []string
	TokenEndpointAuth string
	HTTPClient        *http.Client
}

// Provider implements signet.OAuthProvider using OIDC discovery.
type Provider struct {
	cfg         Config
	doc         *oidc.Document
	client      *http.Client
	keys        *oidc.KeySet
	issuer      string
	algs        []string
	authURL     string
	tokenURL    string
	userInfoURL string
	authMethods []string
}

// NewProvider fetches discovery once and returns a configured Provider.
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.ProviderID == "" || cfg.ClientID == "" {
		return nil, errors.New("oidc: ProviderID and ClientID are required")
	}
	if cfg.ProviderID == "google" || cfg.ProviderID == "github" {
		return nil, errors.New("oidc: reserved provider ID")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	client = oidc.SafeHTTP(client)
	issuer := cfg.Issuer
	if issuer == "" && cfg.DiscoveryURL != "" {
		parsed, err := url.Parse(cfg.DiscoveryURL)
		if err != nil || parsed.Scheme != "https" || parsed.Path == "" {
			return nil, errors.New("oidc: DiscoveryURL must be an https URL with a path")
		}
		issuer = parsed.Scheme + "://" + parsed.Host
	}
	doc, err := oidc.Discover(ctx, client, issuer)
	if err != nil {
		return nil, err
	}
	if cfg.Issuer != "" && cfg.Issuer != doc.Issuer {
		return nil, errors.New("oidc: configured issuer does not match discovery")
	}
	algorithms := intersect(doc.Algorithms)
	if len(algorithms) == 0 {
		return nil, errors.New("oidc: no supported signing algorithms")
	}
	authURL := firstNonEmpty(cfg.AuthorizationURL, doc.AuthorizationEndpoint)
	if err := requireHTTPS(authURL, "authorization endpoint"); err != nil {
		return nil, err
	}
	tokenURL := firstNonEmpty(cfg.TokenURL, doc.TokenEndpoint)
	if err := requireHTTPS(tokenURL, "token endpoint"); err != nil {
		return nil, err
	}
	userInfoURL := firstNonEmpty(cfg.UserInfoURL, doc.UserInfoEndpoint)
	if userInfoURL != "" {
		if err := requireHTTPS(userInfoURL, "userinfo endpoint"); err != nil {
			return nil, err
		}
	}
	jwksURI := firstNonEmpty(cfg.JWKSURI, doc.JWKSURI)
	keys := (*oidc.KeySet)(nil)
	if jwksURI != "" {
		if err := requireHTTPS(jwksURI, "jwks URI"); err != nil {
			return nil, err
		}
		keys = oidc.NewKeySet(client, jwksURI)
	}
	provider := &Provider{
		cfg: cfg, doc: doc, client: client, keys: keys,
		issuer: doc.Issuer, algs: algorithms, authURL: authURL,
		tokenURL: tokenURL, userInfoURL: userInfoURL, authMethods: doc.AuthMethods,
	}
	return provider, nil
}

func intersect(discovered []string) []string {
	out := make([]string, 0, len(discovered))
	for _, candidate := range discovered {
		for _, allowed := range allowedAlgorithms {
			if candidate == allowed {
				out = append(out, candidate)
				break
			}
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func requireHTTPS(raw, field string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("oidc: %s must be an absolute https URL", field)
	}
	return nil
}

// Name returns the configured Provider ID.
func (p *Provider) Name() string { return p.cfg.ProviderID }

// AuthURL builds the OIDC authorization URL with PKCE.
func (p *Provider) AuthURL(_ string, redirectURI, state, challenge string) string {
	return p.authURLWithNonce(clientIDFromConfig(p), redirectURI, state, challenge, "")
}

func clientIDFromConfig(p *Provider) string { return p.cfg.ClientID }

// AuthURLWithNonce builds an authorization URL that binds an OIDC nonce.
func (p *Provider) AuthURLWithNonce(_ string, redirectURI, state, challenge, nonce string) string {
	return p.authURLWithNonce(p.cfg.ClientID, redirectURI, state, challenge, nonce)
}

func (p *Provider) authURLWithNonce(clientID, redirectURI, state, challenge, nonce string) string {
	scopes := p.cfg.Scopes
	hasOpenID := false
	for _, scope := range scopes {
		if scope == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		scopes = append([]string{"openid"}, scopes...)
	}
	query := url.Values{}
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	if nonce != "" {
		query.Set("nonce", nonce)
	}
	separator := "?"
	if strings.Contains(p.authURL, "?") {
		separator = "&"
	}
	return p.authURL + separator + query.Encode()
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

type userInfoResponse struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

func (p *Provider) authStyle() string {
	if p.cfg.TokenEndpointAuth == "client_secret_post" {
		return "post"
	}
	if p.cfg.TokenEndpointAuth == "client_secret_basic" {
		return "basic"
	}
	for _, method := range p.authMethods {
		if method == "client_secret_basic" {
			return "basic"
		}
		if method == "client_secret_post" {
			return "post"
		}
	}
	return "basic"
}

func (p *Provider) exchangeTokens(ctx context.Context, code, verifier, redirectURI string) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	style := p.authStyle()
	if style == "post" {
		form.Set("client_id", p.cfg.ClientID)
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if style == "basic" {
		req.SetBasicAuth(p.cfg.ClientID, p.cfg.ClientSecret)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: token status %d", resp.StatusCode)
	}
	var tokens tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, fmt.Errorf("oidc: decode token response: %w", err)
	}
	if tokens.AccessToken == "" {
		return nil, errors.New("oidc: token response has no access token")
	}
	return &tokens, nil
}

func (p *Provider) userInfo(ctx context.Context, accessToken string) (*userInfoResponse, error) {
	if p.userInfoURL == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: userinfo status %d", resp.StatusCode)
	}
	var info userInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("oidc: decode userinfo: %w", err)
	}
	return &info, nil
}

func (p *Provider) exchange(ctx context.Context, code, verifier, redirectURI, nonce string) (*signet.OAuthIdentity, error) {
	tokens, err := p.exchangeTokens(ctx, code, verifier, redirectURI)
	if err != nil {
		return nil, err
	}
	var verified *oidc.Claims
	if tokens.IDToken != "" && p.keys != nil {
		verified, err = oidc.Verify(ctx, p.keys, tokens.IDToken, p.issuer, p.cfg.ClientID, p.algs)
		if err != nil {
			return nil, err
		}
		if nonce != "" && verified.Nonce != nonce {
			return nil, errors.New("oidc: id token nonce mismatch")
		}
	}
	info, err := p.userInfo(ctx, tokens.AccessToken)
	if err != nil {
		return nil, err
	}
	var subject, email string
	var emailVerified bool
	if verified != nil {
		subject = verified.Subject
		email = verified.Email
		emailVerified = verified.EmailVerified
	}
	if info != nil {
		if subject == "" {
			subject = info.Subject
		} else if info.Subject != "" && info.Subject != subject {
			return nil, errors.New("oidc: userinfo subject mismatch")
		}
		if email == "" {
			email = info.Email
		}
		if !emailVerified && info.EmailVerified {
			emailVerified = true
		}
	}
	if subject == "" || email == "" {
		return nil, signet.ErrOAuthEmailNotVerified
	}
	return &signet.OAuthIdentity{
		Provider: p.cfg.ProviderID, ProviderUserID: subject,
		Email: email, EmailVerified: emailVerified,
	}, nil
}

// Exchange redeems an authorization code and verifies the resulting identity.
func (p *Provider) Exchange(ctx context.Context, code, verifier, redirectURI string) (*signet.OAuthIdentity, error) {
	return p.exchange(ctx, code, verifier, redirectURI, "")
}

// ExchangeWithNonce also binds the ID token to the OIDC nonce.
func (p *Provider) ExchangeWithNonce(ctx context.Context, code, verifier, redirectURI, nonce string) (*signet.OAuthIdentity, error) {
	return p.exchange(ctx, code, verifier, redirectURI, nonce)
}
