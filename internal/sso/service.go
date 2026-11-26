// Package sso implements per-organization OIDC single sign-on.
package sso

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shakibdshy/signet-auth/internal/audit"
	"github.com/shakibdshy/signet-auth/internal/core"
	"github.com/shakibdshy/signet-auth/internal/samlsp"
	"github.com/shakibdshy/signet-auth/internal/secret"
	"github.com/shakibdshy/signet-auth/internal/session"
	"github.com/shakibdshy/signet-auth/internal/token"
)

const stateTTL = 5 * time.Minute

// Deps holds the collaborators for SSO operations.
type Deps struct {
	Config   *core.Config
	Store    core.Store
	Tokens   *token.Service
	Sessions *session.Service
	Logger   *slog.Logger
	Resolve  func(context.Context, string) (*core.User, error)
	SAML     *samlsp.Service
}

// Service implements the public SSO operations.
type Service struct{ deps Deps }

// New returns a Service.
func New(deps Deps) *Service { return &Service{deps: deps} }

// Enabled reports whether SSO is configured.
func (s *Service) Enabled() bool {
	return s.deps.Config.SSO != nil && s.deps.Config.SSO.Connections != nil
}

func (s *Service) actor(ctx context.Context, raw string) (*core.User, bool) {
	if s.deps.Resolve == nil {
		return nil, false
	}
	user, err := s.deps.Resolve(ctx, raw)
	return user, err == nil && user != nil
}

func (s *Service) owns(ctx context.Context, orgID, userID string) bool {
	if s.deps.Config.OrganizationStore == nil {
		return true
	}
	role, err := s.deps.Config.OrganizationStore.MemberRole(ctx, orgID, userID)
	return err == nil && (role == "owner" || role == "admin")
}

func (s *Service) fresh(ctx context.Context, raw string) bool {
	if raw == "" {
		return false
	}
	fresh, err := s.deps.Sessions.IsFreshWithin(ctx, raw, s.deps.Config.Accounts.FreshWindow)
	return err == nil && fresh
}

func (s *Service) emit(ctx context.Context, name, userID, orgID, outcome string) {
	audit.Emit(ctx, s.deps.Config.AuditSink, s.deps.Logger, core.AuditEvent{
		Name: name, UserID: userID, Outcome: outcome,
		Metadata: map[string]string{"organization_id": orgID},
	})
}

// ClaimInput carries a safe view of a connection for creation.
func (s *Service) fromCreate(in core.CreateSSOConnectionInput) *core.SSOConnection {
	role := in.DefaultRole
	if role == "" {
		role = s.deps.Config.SSO.DefaultRole
	}
	if role == "" {
		role = "member"
	}
	return &core.SSOConnection{
		ID: secret.NewID(), OrganizationID: in.OrganizationID, Issuer: in.Issuer,
		ClientID: in.ClientID, ClientSecret: in.ClientSecret, Domains: in.Domains, DefaultRole: role,
		Protocol: in.Protocol, Metadata: in.Metadata,
	}
}

// CreateConnection stores a verified SSO connection.
func (s *Service) CreateConnection(ctx context.Context, in core.CreateSSOConnectionInput) (*core.SSOConnectionInfo, error) {
	actor, ok := s.actor(ctx, in.SessionToken)
	if !s.Enabled() || !ok || !s.fresh(ctx, in.SessionToken) || !s.owns(ctx, in.OrganizationID, actor.ID) {
		return nil, core.ErrForbidden
	}
	for _, domain := range in.Domains {
		if s.deps.Config.SSO.VerifyDomain == nil || !s.deps.Config.SSO.VerifyDomain(ctx, in.OrganizationID, strings.ToLower(domain)) {
			s.emit(ctx, audit.SSODomainUnverified, in.OrganizationID, in.OrganizationID, "denied")
			return nil, core.ErrSSODomainNotVerified
		}
	}
	connection := s.fromCreate(in)
	if err := s.deps.Config.SSO.Connections.Create(ctx, connection); err != nil {
		return nil, err
	}
	s.emit(ctx, audit.SSOConnectionCreated, in.OrganizationID, in.OrganizationID, "success")
	return &core.SSOConnectionInfo{
		ID: connection.ID, OrganizationID: connection.OrganizationID,
		Issuer: connection.Issuer, Domains: connection.Domains, DefaultRole: connection.DefaultRole,
	}, nil
}

// ListConnections returns safe connection views.
func (s *Service) ListConnections(ctx context.Context, sessionToken string) ([]*core.SSOConnectionInfo, error) {
	actor, ok := s.actor(ctx, sessionToken)
	if !s.Enabled() || !ok || !s.fresh(ctx, sessionToken) {
		return nil, core.ErrForbidden
	}
	connections, err := s.deps.Config.SSO.Connections.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*core.SSOConnectionInfo, 0, len(connections))
	for _, c := range connections {
		if !s.owns(ctx, c.OrganizationID, actor.ID) {
			continue
		}
		out = append(out, &core.SSOConnectionInfo{
			ID: c.ID, OrganizationID: c.OrganizationID, Issuer: c.Issuer,
			Domains: c.Domains, DefaultRole: c.DefaultRole,
		})
	}
	return out, nil
}

// DeleteConnection removes a connection after a freshness check.
func (s *Service) DeleteConnection(ctx context.Context, id, sessionToken string) error {
	actor, ok := s.actor(ctx, sessionToken)
	if !s.Enabled() || !ok || !s.fresh(ctx, sessionToken) {
		return core.ErrForbidden
	}
	connection, err := s.deps.Config.SSO.Connections.ByID(ctx, id)
	if err != nil || !s.owns(ctx, connection.OrganizationID, actor.ID) {
		return core.ErrForbidden
	}
	if err := s.deps.Config.SSO.Connections.Delete(ctx, id); err != nil {
		return err
	}
	s.emit(ctx, audit.SSOConnectionDeleted, id, "", "success")
	return nil
}

// StartSAML begins an SP-initiated SAML ceremony.
func (s *Service) StartSAML(ctx context.Context, in core.SAMLStartInput) (*core.SAMLStartResult, error) {
	if !s.Enabled() || s.deps.SAML == nil {
		return nil, core.ErrForbidden
	}
	connection, err := s.resolveConnection(ctx, core.SSOStartInput{
		OrganizationID: in.OrganizationID, Email: in.Email,
	})
	if err != nil || connection.Protocol != "saml" {
		return nil, core.ErrSAMLConnectionNotFound
	}
	spURL, err := url.Parse(s.deps.Config.AppURL)
	if err != nil || spURL.Host == "" {
		return nil, core.ErrSAMLConnectionNotFound
	}
	connection.SPHost = spURL.Host
	connection.SPEntityID = strings.TrimRight(s.deps.Config.AppURL, "/") + "/saml/metadata"
	result, err := s.deps.SAML.Start(ctx, connection, strings.TrimRight(s.deps.Config.AppURL, "/")+"/saml/acs")
	if err != nil {
		return nil, err
	}
	stateData, _ := json.Marshal(struct {
		Protocol     string `json:"protocol"`
		ConnectionID string `json:"connection_id"`
	}{"saml", connection.ID})
	state, _, err := s.deps.Tokens.IssueWithData(ctx, "", core.TokenOAuthState, stateTTL, string(stateData))
	if err != nil {
		return nil, err
	}
	return &core.SAMLStartResult{URL: result.URL, State: state, RequestID: result.RequestID}, nil
}

// CompleteSAML validates an assertion and provisions a Session.
func (s *Service) CompleteSAML(ctx context.Context, state string, request *http.Request) (*core.SAMLACSResult, error) {
	if !s.Enabled() || s.deps.SAML == nil {
		return nil, core.ErrForbidden
	}
	if _, err := s.deps.Tokens.Consume(ctx, core.TokenOAuthState, state); err != nil {
		s.emit(ctx, audit.SSODomainUnverified, "", "", "denied")
		return nil, core.ErrSAMLInvalidAssertion
	}
	raw, err := token.ParseData(state)
	if err != nil {
		return nil, core.ErrSAMLInvalidAssertion
	}
	var data struct {
		Protocol     string `json:"protocol"`
		ConnectionID string `json:"connection_id"`
	}
	if json.Unmarshal([]byte(raw), &data) != nil || data.Protocol != "saml" {
		return nil, core.ErrSAMLInvalidAssertion
	}
	connection, err := s.deps.Config.SSO.Connections.ByID(ctx, data.ConnectionID)
	if err != nil {
		return nil, core.ErrSAMLConnectionNotFound
	}
	spURL, _ := url.Parse(s.deps.Config.AppURL)
	connection.SPHost = spURL.Host
	connection.SPEntityID = strings.TrimRight(s.deps.Config.AppURL, "/") + "/saml/metadata"
	assertion, err := s.deps.SAML.ACS(ctx, connection, strings.TrimRight(s.deps.Config.AppURL, "/")+"/saml/acs", request.FormValue("SAMLResponse"))
	if err != nil {
		s.emit(ctx, audit.SSOSignIn, "", connection.OrganizationID, "denied")
		return nil, err
	}
	claims := &core.SSOClaims{
		Subject: assertion.NameID,
		Email:   firstAttribute(assertion.Attributes, "email", "emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
		Name:    firstAttribute(assertion.Attributes, "name", "displayname"),
	}
	verified := firstAttribute(assertion.Attributes, "email_verified")
	claims.EmailVerified = strings.EqualFold(verified, "true")
	if s.deps.Config.SSO.MapClaims != nil {
		if mapped := s.deps.Config.SSO.MapClaims(ctx, claims); mapped != nil {
			claims = mapped
		}
	}
	if claims.Subject == "" || claims.Email == "" || !claims.EmailVerified {
		return nil, core.ErrSAMLInvalidAssertion
	}
	user, err := s.provision(ctx, &core.OAuthIdentity{
		ProviderUserID: claims.Subject, Email: claims.Email, EmailVerified: claims.EmailVerified,
	}, connection)
	if err != nil {
		return nil, err
	}
	sessionToken, err := s.deps.Sessions.Create(ctx, user.ID, "")
	if err != nil {
		return nil, err
	}
	s.emit(ctx, audit.SSOSignIn, user.ID, connection.OrganizationID, "success")
	return &core.SAMLACSResult{SessionToken: sessionToken, OrganizationID: connection.OrganizationID}, nil
}

func firstAttribute(attributes map[string][]string, names ...string) string {
	for _, name := range names {
		if values := attributes[name]; len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// resolveConnection finds a connection by Organization ID or email domain.
func (s *Service) resolveConnection(ctx context.Context, in core.SSOStartInput) (*core.SSOConnection, error) {
	store := s.deps.Config.SSO.Connections
	if in.OrganizationID != "" {
		connection, err := store.ByOrganization(ctx, in.OrganizationID)
		if err != nil {
			return nil, core.ErrSSOConnectionNotFound
		}
		return connection, nil
	}
	at := strings.LastIndex(in.Email, "@")
	if at < 0 {
		return nil, core.ErrSSOConnectionNotFound
	}
	connection, err := store.ByDomain(ctx, strings.ToLower(in.Email[at+1:]))
	if err != nil {
		return nil, core.ErrSSOConnectionNotFound
	}
	return connection, nil
}

// Start begins an SSO ceremony and returns the provider URL.
func (s *Service) Start(ctx context.Context, in core.SSOStartInput) (*core.SSOStartResult, error) {
	if !s.Enabled() || s.deps.Config.SSO.Provider == nil {
		return nil, core.ErrForbidden
	}
	connection, err := s.resolveConnection(ctx, in)
	if err != nil {
		return nil, core.ErrSSOConnectionNotFound
	}
	for _, domain := range connection.Domains {
		if s.deps.Config.SSO.VerifyDomain == nil || !s.deps.Config.SSO.VerifyDomain(ctx, connection.OrganizationID, strings.ToLower(domain)) {
			return nil, core.ErrSSOConnectionNotFound
		}
	}
	provider, err := s.deps.Config.SSO.Provider(ctx, connection)
	if err != nil {
		return nil, core.ErrSSOInvalidAssertion
	}
	verifier := secret.NewToken()
	nonce := secret.NewToken()
	data, _ := json.Marshal(struct {
		ConnectionID string `json:"connection_id"`
		Verifier     string `json:"verifier"`
		Nonce        string `json:"nonce"`
		RedirectURI  string `json:"redirect_uri"`
	}{connection.ID, verifier, nonce, in.RedirectURI})
	state, _, err := s.deps.Tokens.IssueWithData(ctx, "", core.TokenOAuthState, stateTTL, string(data))
	if err != nil {
		return nil, err
	}
	withNonce, ok := provider.(interface {
		AuthURLWithNonce(string, string, string, string, string) string
	})
	if !ok {
		return nil, core.ErrSSOInvalidAssertion
	}
	challenge := challengeFor(verifier)
	authURL := withNonce.AuthURLWithNonce(connection.ClientID, in.RedirectURI, state, challenge, nonce)
	return &core.SSOStartResult{URL: authURL, State: state}, nil
}

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Callback verifies an assertion and provisions a Session.
func (s *Service) Callback(ctx context.Context, in core.SSOCallbackInput) (*core.SSOCallbackResult, error) {
	if !s.Enabled() {
		return nil, core.ErrForbidden
	}
	if _, err := s.deps.Tokens.Consume(ctx, core.TokenOAuthState, in.State); err != nil {
		return nil, core.ErrSSOInvalidAssertion
	}
	raw, err := token.ParseData(in.State)
	if err != nil {
		return nil, core.ErrSSOInvalidAssertion
	}
	var data struct {
		ConnectionID string `json:"connection_id"`
		Verifier     string `json:"verifier"`
		Nonce        string `json:"nonce"`
		RedirectURI  string `json:"redirect_uri"`
	}
	if json.Unmarshal([]byte(raw), &data) != nil || data.ConnectionID == "" {
		return nil, core.ErrSSOInvalidAssertion
	}
	connection, err := s.deps.Config.SSO.Connections.ByID(ctx, data.ConnectionID)
	if err != nil {
		return nil, core.ErrSSOConnectionNotFound
	}
	provider, err := s.deps.Config.SSO.Provider(ctx, connection)
	if err != nil {
		return nil, core.ErrSSOInvalidAssertion
	}
	withNonce, ok := provider.(interface {
		ExchangeWithNonce(context.Context, string, string, string, string) (*core.OAuthIdentity, error)
	})
	if !ok {
		return nil, core.ErrSSOInvalidAssertion
	}
	identity, err := withNonce.ExchangeWithNonce(ctx, in.Code, data.Verifier, data.RedirectURI, data.Nonce)
	if err != nil || identity == nil || identity.Email == "" || !identity.EmailVerified || identity.ProviderUserID == "" {
		return nil, core.ErrSSOInvalidAssertion
	}
	user, err := s.provision(ctx, identity, connection)
	if err != nil {
		return nil, err
	}
	sessionToken, err := s.deps.Sessions.Create(ctx, user.ID, "")
	if err != nil {
		return nil, err
	}
	s.emit(ctx, audit.SSOSignIn, user.ID, "", "success")
	return &core.SSOCallbackResult{SessionToken: sessionToken, OrganizationID: connection.OrganizationID}, nil
}

func (s *Service) provision(ctx context.Context, identity *core.OAuthIdentity, connection *core.SSOConnection) (*core.User, error) {
	provider := "sso:" + connection.ID
	account, err := s.deps.Store.AccountByProvider(ctx, provider, identity.ProviderUserID)
	if err == nil {
		linked, err := s.deps.Store.UserByID(ctx, account.UserID)
		if err != nil || linked.Disabled || !linked.EmailVerified ||
			!strings.EqualFold(linked.Email, identity.Email) {
			return nil, core.ErrSSOInvalidAssertion
		}
		return linked, nil
	}
	user, err := s.deps.Store.UserByEmail(ctx, identity.Email)
	if err == nil {
		if !user.EmailVerified || user.Disabled {
			return nil, core.ErrSSOInvalidAssertion
		}
	} else {
		now := s.deps.Config.Clock.Now()
		user = &core.User{ID: secret.NewID(), Email: identity.Email, EmailVerified: true, CreatedAt: now, UpdatedAt: now}
		if err := s.deps.Store.CreateUser(ctx, user); err != nil {
			return nil, err
		}
	}
	account = &core.Account{
		ID: secret.NewID(), UserID: user.ID, Provider: provider,
		ProviderUserID: identity.ProviderUserID, Email: identity.Email,
	}
	if err := s.deps.Store.CreateAccount(ctx, account); err != nil {
		return nil, err
	}
	if s.deps.Config.OrganizationStore != nil && connection.OrganizationID != "" {
		role := connection.DefaultRole
		if role == "" {
			role = s.deps.Config.SSO.DefaultRole
		}
		if role == "" {
			role = "member"
		}
		if _, err := s.deps.Config.OrganizationStore.MemberRole(ctx, connection.OrganizationID, user.ID); err != nil {
			if err := s.deps.Config.OrganizationStore.AddMember(ctx, connection.OrganizationID, user.ID, role); err != nil {
				return nil, err
			}
		}
	}
	return user, nil
}
