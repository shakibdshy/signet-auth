// Package oidc implements discovery and ID-token verification for generic
// OAuth/OIDC providers. It is used by the public oauth/oidc adapter.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Document is the subset of OIDC discovery metadata Signet consumes.
type Document struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	Algorithms            []string `json:"id_token_signing_alg_values_supported"`
	AuthMethods           []string `json:"token_endpoint_auth_methods_supported"`
}

// SafeHTTP returns a client that refuses redirects, with a bounded timeout.
func SafeHTTP(client *http.Client) *http.Client {
	cloned := *client
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("oidc: redirects are not allowed")
	}
	if cloned.Timeout == 0 {
		cloned.Timeout = 10 * time.Second
	}
	return &cloned
}

// RequireHTTPS validates a metadata URL.
func RequireHTTPS(raw, field string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("oidc: %s must be an absolute https URL", field)
	}
	return nil
}

// Discover fetches the well-known document for an issuer. An explicit
// discoveryURL overrides the derived well-known URL.
func Discover(ctx context.Context, client *http.Client, issuer, discoveryURL string) (*Document, error) {
	if discoveryURL == "" {
		if err := RequireHTTPS(issuer, "issuer"); err != nil {
			return nil, err
		}
		discoveryURL = strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	}
	if err := RequireHTTPS(discoveryURL, "discovery URL"); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: discovery status %d", resp.StatusCode)
	}
	var doc Document
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("oidc: decode discovery: %w", err)
	}
	if err := RequireHTTPS(doc.Issuer, "issuer in discovery document"); err != nil {
		return nil, err
	}
	for name, value := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"userinfo_endpoint":      doc.UserInfoEndpoint,
		"jwks_uri":               doc.JWKSURI,
	} {
		if value != "" {
			if err := RequireHTTPS(value, name); err != nil {
				return nil, err
			}
		}
	}
	return &doc, nil
}
