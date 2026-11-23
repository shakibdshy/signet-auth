package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
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
