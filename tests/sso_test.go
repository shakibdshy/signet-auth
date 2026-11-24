package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

type fakeSSOConnectionStore struct {
	connections map[string]*signet.SSOConnection
	byDomain    map[string]*signet.SSOConnection
	byOrg       map[string]*signet.SSOConnection
}

func newFakeSSOConnectionStore() *fakeSSOConnectionStore {
	return &fakeSSOConnectionStore{
		connections: make(map[string]*signet.SSOConnection),
		byDomain:    make(map[string]*signet.SSOConnection),
		byOrg:       make(map[string]*signet.SSOConnection),
	}
}

func (s *fakeSSOConnectionStore) Create(_ context.Context, c *signet.SSOConnection) error {
	clone := *c
	s.connections[c.ID] = &clone
	s.byOrg[c.OrganizationID] = &clone
	for _, d := range c.Domains {
		s.byDomain[d] = &clone
	}
	return nil
}
func (s *fakeSSOConnectionStore) ByOrganization(_ context.Context, id string) (*signet.SSOConnection, error) {
	c, ok := s.byOrg[id]
	if !ok {
		return nil, signet.ErrNotFound
	}
	return c, nil
}
func (s *fakeSSOConnectionStore) ByID(_ context.Context, id string) (*signet.SSOConnection, error) {
	c, ok := s.connections[id]
	if !ok {
		return nil, signet.ErrNotFound
	}
	return c, nil
}
func (s *fakeSSOConnectionStore) ByDomain(_ context.Context, domain string) (*signet.SSOConnection, error) {
	c, ok := s.byDomain[domain]
	if !ok {
		return nil, signet.ErrNotFound
	}
	return c, nil
}
func (s *fakeSSOConnectionStore) List(context.Context) ([]*signet.SSOConnection, error) {
	out := make([]*signet.SSOConnection, 0, len(s.connections))
	for _, c := range s.connections {
		clone := *c
		out = append(out, &clone)
	}
	return out, nil
}
func (s *fakeSSOConnectionStore) Delete(_ context.Context, id string) error {
	delete(s.connections, id)
	return nil
}

type fakeSSOProvider struct {
	identity *signet.OAuthIdentity
	fail     bool
	nonce    string
}

func (p *fakeSSOProvider) Name() string { return "sso:fake" }
func (p *fakeSSOProvider) AuthURL(_ string, redirectURI, state, challenge string) string {
	return p.AuthURLWithNonce("", redirectURI, state, challenge, "")
}
func (p *fakeSSOProvider) AuthURLWithNonce(_ string, _ string, state, _ string, nonce string) string {
	p.nonce = nonce
	return "https://idp.example.com/authorize?state=" + state + "&nonce=" + nonce
}
func (p *fakeSSOProvider) Exchange(ctx context.Context, code, verifier, redirectURI string) (*signet.OAuthIdentity, error) {
	return p.ExchangeWithNonce(ctx, code, verifier, redirectURI, "")
}
func (p *fakeSSOProvider) ExchangeWithNonce(_ context.Context, _, _, _, nonce string) (*signet.OAuthIdentity, error) {
	if p.fail || p.identity == nil || nonce != p.nonce {
		return nil, errors.New("assertion rejected")
	}
	return p.identity, nil
}

func ssoClient(t *testing.T, provider *fakeSSOProvider, verify func(context.Context, string, string) bool) (*signet.Client, string, string) {
	t.Helper()
	store := testutil.NewStore()
	connections := newFakeSSOConnectionStore()
	orgs := newFakeOrganizationStore()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AppURL = "https://app.example.com"
	cfg.OrganizationStore = orgs
	cfg.Authorizer = &fakeAuthorizer{allowed: map[string]bool{"organizations:create": true}}
	cfg.SSO = &signet.SSOConfig{
		Connections: connections, VerifyDomain: verify,
		Provider: func(context.Context, *signet.SSOConnection) (signet.OAuthProvider, error) {
			return provider, nil
		},
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
	created, err := client.CreateOrganization(ctx, signet.CreateOrganizationInput{
		OwnerID: signUp.User.ID, Name: "Acme", SessionToken: session.SessionToken,
	})
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	return client, session.SessionToken, created.Organization.ID
}

func verifyTrue(context.Context, string, string) bool { return true }

func TestSSOConnectionAndSignIn(t *testing.T) {
	provider := &fakeSSOProvider{identity: &signet.OAuthIdentity{
		Provider: "sso:fake", ProviderUserID: "subject-1",
		Email: "member@acme.com", EmailVerified: true,
	}}
	client, token, orgID := ssoClient(t, provider, verifyTrue)
	ctx := context.Background()
	created, err := client.CreateSSOConnection(ctx, signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Issuer: "https://idp.example.com",
		ClientID: "client", ClientSecret: "secret", Domains: []string{"acme.com"},
		SessionToken: token,
	})
	if err != nil || created.ID == "" {
		t.Fatalf("connection = %+v err = %v", created, err)
	}
	start, err := client.StartSSOSignIn(ctx, signet.SSOStartInput{Email: "member@acme.com"})
	if err != nil || start.URL == "" || start.State == "" {
		t.Fatalf("start = %+v err = %v", start, err)
	}
	result, err := client.CompleteSSOSignIn(ctx, signet.SSOCallbackInput{State: start.State, Code: "code"})
	if err != nil || result.SessionToken == "" {
		t.Fatalf("callback = %+v err = %v", result, err)
	}
	if err := client.VerifyFreshSession(ctx, result.SessionToken); err != nil {
		t.Fatalf("session not valid: %v", err)
	}
	if _, err := client.CompleteSSOSignIn(ctx, signet.SSOCallbackInput{State: start.State, Code: "code"}); !errors.Is(err, signet.ErrSSOInvalidAssertion) {
		t.Fatalf("replay error = %v", err)
	}
	accounts, _ := client.ListAccounts(ctx, signet.ListAccountsInput{})
	_ = accounts
}

func TestSSODomainNotVerified(t *testing.T) {
	provider := &fakeSSOProvider{}
	client, token, orgID := ssoClient(t, provider, func(context.Context, string, string) bool { return false })
	_, err := client.CreateSSOConnection(context.Background(), signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Issuer: "https://idp.example.com",
		Domains: []string{"acme.com"}, SessionToken: token,
	})
	if !errors.Is(err, signet.ErrSSODomainNotVerified) {
		t.Fatalf("unverified domain error = %v", err)
	}
}

func TestSSOUnverifiedEmailRejected(t *testing.T) {
	provider := &fakeSSOProvider{identity: &signet.OAuthIdentity{
		ProviderUserID: "subject-2", Email: "member@acme.com", EmailVerified: false,
	}}
	client, token, orgID := ssoClient(t, provider, verifyTrue)
	ctx := context.Background()
	if _, err := client.CreateSSOConnection(ctx, signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Issuer: "https://idp.example.com",
		Domains: []string{"acme.com"}, SessionToken: token,
	}); err != nil {
		t.Fatalf("connection: %v", err)
	}
	start, err := client.StartSSOSignIn(ctx, signet.SSOStartInput{Email: "member@acme.com"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := client.CompleteSSOSignIn(ctx, signet.SSOCallbackInput{State: start.State, Code: "code"}); !errors.Is(err, signet.ErrSSOInvalidAssertion) {
		t.Fatalf("unverified assertion error = %v", err)
	}
}

func TestSSOUnknownConnectionGeneric(t *testing.T) {
	provider := &fakeSSOProvider{}
	client, _, _ := ssoClient(t, provider, verifyTrue)
	_, err := client.StartSSOSignIn(context.Background(), signet.SSOStartInput{Email: "nobody@unknown.com"})
	if !errors.Is(err, signet.ErrSSOConnectionNotFound) {
		t.Fatalf("unknown connection error = %v", err)
	}
}

func TestSSODisabled(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.StartSSOSignIn(context.Background(), signet.SSOStartInput{}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("disabled error = %v", err)
	}
}

func TestSSOConnectionCRUDRequiresFreshSession(t *testing.T) {
	provider := &fakeSSOProvider{}
	client, _, orgID := ssoClient(t, provider, verifyTrue)
	ctx := context.Background()
	if _, err := client.CreateSSOConnection(ctx, signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Domains: []string{"acme.com"}, SessionToken: "stale",
	}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("stale create error = %v", err)
	}
	if _, err := client.ListSSOConnections(ctx, "stale"); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("stale list error = %v", err)
	}
}

func TestSSOHTTPEndpoints(t *testing.T) {
	provider := &fakeSSOProvider{identity: &signet.OAuthIdentity{
		ProviderUserID: "subject-3", Email: "web@acme.com", EmailVerified: true,
	}}
	client, token, orgID := ssoClient(t, provider, verifyTrue)
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	cookies := &http.Cookie{Name: "__Host-signet_session", Value: token, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	createReq := httptest.NewRequest(http.MethodPost, "/sso/connections",
		strings.NewReader(`{"organization_id":"`+orgID+`","issuer":"https://idp.example.com","domains":["acme.com"]}`))
	createReq.AddCookie(cookies)
	createReq.AddCookie(csrfCookie)
	createReq.Header.Set("X-CSRF-Token", csrfToken)
	rr := httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, createReq)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", rr.Code, rr.Body.String())
	}
	startReq := httptest.NewRequest(http.MethodPost, "/sso/start", strings.NewReader(`{"email":"web@acme.com"}`))
	rr = httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, startReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("start status = %d body = %s", rr.Code, rr.Body.String())
	}
	var start struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &start); err != nil || start.State == "" {
		t.Fatalf("decode = %v body = %s", err, rr.Body.String())
	}
	callbackReq := httptest.NewRequest(http.MethodGet, "/sso/callback?state="+start.State+"&code=code", nil)
	rr = httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, callbackReq)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "session_token") {
		t.Fatalf("callback status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestSSOStartHidesUnverifiedDomain(t *testing.T) {
	provider := &fakeSSOProvider{}
	verified := true
	client, token, orgID := ssoClient(t, provider, func(context.Context, string, string) bool { return verified })
	ctx := context.Background()
	if _, err := client.CreateSSOConnection(ctx, signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Domains: []string{"acme.com"}, SessionToken: token,
	}); err != nil {
		t.Fatalf("setup connection: %v", err)
	}
	verified = false
	_, err := client.StartSSOSignIn(ctx, signet.SSOStartInput{Email: "member@acme.com"})
	if !errors.Is(err, signet.ErrSSOConnectionNotFound) {
		t.Fatalf("unverified start error = %v, want generic not-found", err)
	}
}

func TestSSOHTTPDeleteConnection(t *testing.T) {
	provider := &fakeSSOProvider{}
	client, token, orgID := ssoClient(t, provider, verifyTrue)
	ctx := context.Background()
	created, err := client.CreateSSOConnection(ctx, signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Issuer: "https://idp.example.com",
		Domains: []string{"acme.com"}, SessionToken: token,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	req := httptest.NewRequest(http.MethodDelete, "/sso/connections",
		strings.NewReader(`{"id":"`+created.ID+`"}`))
	req.AddCookie(&http.Cookie{Name: "__Host-signet_session", Value: token, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", csrfToken)
	rr := httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status = %d body = %s", rr.Code, rr.Body.String())
	}
}
