package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"errors"
	"testing"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/idp"
	"github.com/russellhaering/gosaml2/v2/types"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

func samlClient(t *testing.T) (*signet.Client, string, string) {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AppURL = "https://app.example.com"
	cfg.Authorizer = &fakeAuthorizer{allowed: map[string]bool{"organizations:create": true}}
	cfg.OrganizationStore = newFakeOrganizationStore()
	cfg.SSO = &signet.SSOConfig{
		Connections:  newFakeSSOConnectionStore(),
		VerifyDomain: func(context.Context, string, string) bool { return true },
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "owner@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	session, err := client.SignIn(ctx, signet.SignInInput{Email: "owner@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	org, err := client.CreateOrganization(ctx, signet.CreateOrganizationInput{
		OwnerID: signUp.User.ID, Name: "Acme", SessionToken: session.SessionToken,
	})
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	return client, session.SessionToken, org.Organization.ID
}

func TestSAMLEnabledAndConnectionRequiresMetadata(t *testing.T) {
	client, token, orgID := samlClient(t)
	ctx := context.Background()
	_, err := client.CreateSSOConnection(ctx, signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Issuer: "https://idp.example.com",
		Protocol: "saml", Domains: []string{"acme.com"}, SessionToken: token,
	})
	if err != nil {
		t.Fatalf("create SAML connection: %v", err)
	}
	_, err = client.StartSAMLSignIn(ctx, signet.SAMLStartInput{OrganizationID: orgID})
	if !errors.Is(err, signet.ErrSAMLConnectionNotFound) {
		t.Fatalf("start without metadata error = %v", err)
	}
}

func TestSAMLOIDCConnectionCannotStartSAML(t *testing.T) {
	client, token, orgID := samlClient(t)
	ctx := context.Background()
	_, err := client.CreateSSOConnection(ctx, signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Issuer: "https://idp.example.com",
		Protocol: "oidc", Domains: []string{"acme.com"}, SessionToken: token,
	})
	if err != nil {
		t.Fatalf("create OIDC connection: %v", err)
	}
	_, err = client.StartSAMLSignIn(ctx, signet.SAMLStartInput{OrganizationID: orgID})
	if !errors.Is(err, signet.ErrSAMLConnectionNotFound) {
		t.Fatalf("OIDC connection started SAML: %v", err)
	}
}

func TestSAMLDisabled(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.StartSAMLSignIn(context.Background(), signet.SAMLStartInput{}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("disabled error = %v", err)
	}
}

type localSAMLIdP struct {
	idp      *idp.IdentityProvider
	metadata string
}

func newLocalSAMLIdP(t *testing.T) *localSAMLIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test IdP"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	provider := &idp.IdentityProvider{
		EntityID: "https://idp.example.com", SSOURL: "https://idp.example.com/sso",
		SigningKeyStore: &saml2.KeyStore{Signer: key, Cert: der},
		SignAssertions:  true, AssertionLifetime: 10 * time.Minute,
		ServiceProviders: map[string]*idp.SPConfig{},
	}
	descriptor, err := provider.Metadata()
	if err != nil {
		t.Fatalf("idp metadata: %v", err)
	}
	metadata, err := xml.Marshal(descriptor)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	return &localSAMLIdP{idp: provider, metadata: string(metadata)}
}

func TestSAMLSignedAssertionEffect(t *testing.T) {
	client, token, orgID := samlClient(t)
	ctx := context.Background()
	spEntityID := "https://app.example.com/saml/metadata"
	idpServer := newLocalSAMLIdP(t)
	idpServer.idp.ServiceProviders[spEntityID] = &idp.SPConfig{}
	if _, err := client.CreateSSOConnection(ctx, signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Protocol: "saml", Issuer: "https://idp.example.com",
		Domains: []string{"acme.com"}, Metadata: idpServer.metadata, SessionToken: token,
	}); err != nil {
		t.Fatalf("connection: %v", err)
	}
	start, err := client.StartSAMLSignIn(ctx, signet.SAMLStartInput{OrganizationID: orgID})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	document, _, err := idpServer.idp.BuildResponseDocument(spEntityID, &idp.AssertionParams{
		NameID: "saml-subject-1", InResponseTo: start.RequestID,
		Recipient: "https://app.example.com/saml/acs", AudienceRestrictions: []string{spEntityID},
		Attributes: []types.Attribute{{
			Name: "email", Values: []types.AttributeValue{{Value: "member@acme.com"}},
		}, {
			Name: "email_verified", Values: []types.AttributeValue{{Value: "true"}},
		}},
	})
	if err != nil {
		t.Fatalf("assertion: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(mustBytes(document.WriteToBytes()))
	form := url.Values{"SAMLResponse": {encoded}, "state": {start.State}}
	request := httptest.NewRequest("POST", "https://app.example.com/saml/acs", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result, err := client.CompleteSAMLSignIn(ctx, start.State, request)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.SessionToken == "" || result.OrganizationID != orgID {
		t.Fatalf("result = %+v", result)
	}
}

func mustBytes(data []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return data
}

func samlResponse(t *testing.T, idpServer *localSAMLIdP, requestID string, attrs []types.Attribute, sign bool) string {
	t.Helper()
	idpServer.idp.SignAssertions = sign
	document, _, err := idpServer.idp.BuildResponseDocument("https://app.example.com/saml/metadata", &idp.AssertionParams{
		NameID: "saml-subject-1", InResponseTo: requestID,
		Recipient:            "https://app.example.com/saml/acs",
		AudienceRestrictions: []string{"https://app.example.com/saml/metadata"},
		Attributes:           attrs,
	})
	if err != nil {
		t.Fatalf("assertion: %v", err)
	}
	return base64.StdEncoding.EncodeToString(mustBytes(document.WriteToBytes()))
}

func samlAttrs(verified string) []types.Attribute {
	return []types.Attribute{
		{Name: "email", Values: []types.AttributeValue{{Value: "member@acme.com"}}},
		{Name: "email_verified", Values: []types.AttributeValue{{Value: verified}}},
	}
}

func TestSAMLRejectsUnsignedAssertion(t *testing.T) {
	client, token, orgID := samlClient(t)
	ctx := context.Background()
	idpServer := newLocalSAMLIdP(t)
	idpServer.idp.ServiceProviders["https://app.example.com/saml/metadata"] = &idp.SPConfig{}
	if _, err := client.CreateSSOConnection(ctx, signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Protocol: "saml", Issuer: "https://idp.example.com",
		Domains: []string{"acme.com"}, Metadata: idpServer.metadata, SessionToken: token,
	}); err != nil {
		t.Fatalf("connection: %v", err)
	}
	start, err := client.StartSAMLSignIn(ctx, signet.SAMLStartInput{OrganizationID: orgID})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	response := samlResponse(t, idpServer, start.RequestID, samlAttrs("true"), false)
	form := url.Values{"SAMLResponse": {response}}
	request := httptest.NewRequest("POST", "https://app.example.com/saml/acs", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := client.CompleteSAMLSignIn(ctx, start.State, request); !errors.Is(err, signet.ErrSAMLInvalidAssertion) {
		t.Fatalf("unsigned assertion error = %v", err)
	}
}

func TestSAMLRejectsUnverifiedEmail(t *testing.T) {
	client, token, orgID := samlClient(t)
	ctx := context.Background()
	idpServer := newLocalSAMLIdP(t)
	idpServer.idp.ServiceProviders["https://app.example.com/saml/metadata"] = &idp.SPConfig{}
	if _, err := client.CreateSSOConnection(ctx, signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Protocol: "saml", Issuer: "https://idp.example.com",
		Domains: []string{"acme.com"}, Metadata: idpServer.metadata, SessionToken: token,
	}); err != nil {
		t.Fatalf("connection: %v", err)
	}
	start, err := client.StartSAMLSignIn(ctx, signet.SAMLStartInput{OrganizationID: orgID})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	response := samlResponse(t, idpServer, start.RequestID, samlAttrs("false"), true)
	form := url.Values{"SAMLResponse": {response}}
	request := httptest.NewRequest("POST", "https://app.example.com/saml/acs", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := client.CompleteSAMLSignIn(ctx, start.State, request); !errors.Is(err, signet.ErrSAMLInvalidAssertion) {
		t.Fatalf("unverified email error = %v", err)
	}
}

func TestSAMLRejectsWrongInResponseTo(t *testing.T) {
	client, token, orgID := samlClient(t)
	ctx := context.Background()
	idpServer := newLocalSAMLIdP(t)
	idpServer.idp.ServiceProviders["https://app.example.com/saml/metadata"] = &idp.SPConfig{}
	if _, err := client.CreateSSOConnection(ctx, signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Protocol: "saml", Issuer: "https://idp.example.com",
		Domains: []string{"acme.com"}, Metadata: idpServer.metadata, SessionToken: token,
	}); err != nil {
		t.Fatalf("connection: %v", err)
	}
	start, err := client.StartSAMLSignIn(ctx, signet.SAMLStartInput{OrganizationID: orgID})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	response := samlResponse(t, idpServer, "not-the-request-id", samlAttrs("true"), true)
	form := url.Values{"SAMLResponse": {response}}
	request := httptest.NewRequest("POST", "https://app.example.com/saml/acs", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := client.CompleteSAMLSignIn(ctx, start.State, request); !errors.Is(err, signet.ErrSAMLReplay) && !errors.Is(err, signet.ErrSAMLInvalidAssertion) {
		t.Fatalf("wrong InResponseTo error = %v", err)
	}
}
