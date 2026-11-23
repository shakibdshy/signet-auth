// Package oidc provides a generic OAuth/OIDC provider adapter for Signet.
package oidc

import (
	"context"
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
	cfg     Config
	doc     *oidc.Document
	client  *http.Client
	keys    *oidc.KeySet
	issuer  string
	algs    []string
	authURL string
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
	query.Set("client_id", p.cfg.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	separator := "?"
	if strings.Contains(p.authURL, "?") {
		separator = "&"
	}
	return p.authURL + separator + query.Encode()
}

// Exchange is implemented in the identity-verification part of the adapter.
func (p *Provider) Exchange(context.Context, string, string, string) (*signet.OAuthIdentity, error) {
	return nil, errors.New("oidc: exchange not configured")
}
