// Package samlsp implements SAML 2.0 Web SSO ceremony handling.
package samlsp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/sp"
	"github.com/shakibdshy/signet/internal/core"
)

// Result carries the browser URL and normalized assertion attributes.
type Result struct {
	URL        string
	RequestID  string
	Attributes map[string][]string
	NameID     string
}

// Service builds SAML ceremonies from pinned IdP metadata.
type Service struct {
	key      *rsa.PrivateKey
	certPEM  []byte
	replay   *sp.MemoryAssertionReplayCache
	requests *sp.MemoryRequestTracker
}

// New returns a Service with an ephemeral SP signing key.
func New() (*Service, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: bigOne()}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &Service{
		key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		replay: sp.NewMemoryAssertionReplayCache(), requests: sp.NewMemoryRequestTracker(10 * time.Minute),
	}, nil
}

func bigOne() *big.Int { return new(big.Int).SetInt64(1) }

func (s *Service) provider(connection *core.SSOConnection, acsURL string) (*sp.ServiceProvider, error) {
	metadata, err := saml2.ParseEntityDescriptor([]byte(connection.Metadata))
	if err != nil || metadata.IDPSSODescriptor == nil {
		return nil, errors.New("invalid SAML metadata")
	}
	var certificates []*x509.Certificate
	for _, descriptor := range metadata.IDPSSODescriptor.KeyDescriptors {
		for _, cert := range descriptor.KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cert.Data))
			if err != nil {
				continue
			}
			if block, _ := pem.Decode(der); block != nil {
				der = block.Bytes
			}
			parsed, err := x509.ParseCertificate(der)
			if err == nil {
				certificates = append(certificates, parsed)
			}
		}
	}
	if len(certificates) == 0 {
		return nil, errors.New("SAML metadata has no signing certificate")
	}
	ssoURL := ""
	for _, service := range metadata.IDPSSODescriptor.SingleSignOnServices {
		parsed, err := url.Parse(service.Location)
		if err == nil && parsed.Scheme == "https" && parsed.Host != "" {
			ssoURL = service.Location
			break
		}
	}
	if ssoURL == "" {
		return nil, errors.New("SAML SSO URL must be HTTPS")
	}
	provider := &sp.ServiceProvider{
		EntityID: connection.SPEntityID, ACSURL: acsURL,
		IDPEntityID: metadata.EntityID, IDPSSOURL: ssoURL,
		IDPSSOBinding:        saml2.BindingHttpPost,
		IDPCertificates:      certificates,
		SPKeyStore:           &saml2.KeyStore{Signer: s.key, Cert: s.certPEM},
		SPSigningKeyStore:    &saml2.KeyStore{Signer: s.key, Cert: s.certPEM},
		AudienceURIs:         []string{connection.SPEntityID},
		AssertionReplayCache: s.replay,
		RequestTracker:       s.requests,
	}
	return provider, nil
}

// Start builds a signed AuthnRequest URL for the IdP.
func (s *Service) Start(_ context.Context, connection *core.SSOConnection, acsURL string) (*Result, error) {
	if connection.Metadata == "" || connection.SPHost == "" {
		return nil, core.ErrSAMLConnectionNotFound
	}
	provider, err := s.provider(connection, acsURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", core.ErrSAMLInvalidAssertion, err)
	}
	document, err := provider.BuildAuthRequestDocument()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", core.ErrSAMLInvalidAssertion, err)
	}
	requestID := ""
	if id := document.Root().SelectAttr("ID"); id != nil {
		requestID = id.Value
	}
	if requestID == "" {
		return nil, core.ErrSAMLInvalidAssertion
	}
	if err := s.requests.StoreRequest(context.Background(), requestID); err != nil {
		return nil, core.ErrSAMLInvalidAssertion
	}
	location, err := provider.BuildAuthURLFromDocument("", document)
	if err != nil {
		return nil, core.ErrSAMLInvalidAssertion
	}
	return &Result{URL: location, RequestID: requestID}, nil
}

// ACS validates an assertion and returns its normalized attributes.
func (s *Service) ACS(ctx context.Context, connection *core.SSOConnection, acsURL string, response string) (*Result, error) {
	provider, err := s.provider(connection, acsURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", core.ErrSAMLInvalidAssertion, err)
	}
	parsed, err := provider.ValidateEncodedResponse(ctx, response)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", core.ErrSAMLInvalidAssertion, err)
	}
	if len(parsed.Assertions) == 0 || parsed.Assertions[0].Subject == nil || parsed.Assertions[0].Subject.NameID == nil {
		return nil, fmt.Errorf("%w: assertion has no subject", core.ErrSAMLInvalidAssertion)
	}
	assertion := parsed.Assertions[0]
	result := &Result{NameID: assertion.Subject.NameID.Value, Attributes: map[string][]string{}}
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			values := make([]string, 0, len(attribute.Values))
			for _, value := range attribute.Values {
				values = append(values, value.Value)
			}
			result.Attributes[attribute.Name] = values
			result.Attributes[attribute.FriendlyName] = append(result.Attributes[attribute.FriendlyName], values...)
		}
	}
	return result, nil
}

// ParseMetadata validates pinned IdP metadata without fetching it remotely.
func ParseMetadata(raw string) error {
	metadata, err := saml2.ParseEntityDescriptor([]byte(raw))
	if err != nil || metadata.IDPSSODescriptor == nil {
		return errors.New("invalid SAML metadata")
	}
	return nil
}
