// Package sso implements per-organization OIDC single sign-on.
package sso

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/shakibdshy/signet/internal/audit"
	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
	"github.com/shakibdshy/signet/internal/session"
	"github.com/shakibdshy/signet/internal/token"
)

const stateTTL = 5 * time.Minute

// Deps holds the collaborators for SSO operations.
type Deps struct {
	Config   *core.Config
	Store    core.Store
	Tokens   *token.Service
	Sessions *session.Service
	Logger   *slog.Logger
}

// Service implements the public SSO operations.
type Service struct{ deps Deps }

// New returns a Service.
func New(deps Deps) *Service { return &Service{deps: deps} }

// Enabled reports whether SSO is configured.
func (s *Service) Enabled() bool {
	return s.deps.Config.SSO != nil && s.deps.Config.SSO.Connections != nil
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
func fromCreate(in core.CreateSSOConnectionInput) *core.SSOConnection {
	role := in.DefaultRole
	if role == "" {
		role = "member"
	}
	return &core.SSOConnection{
		ID: secret.NewID(), OrganizationID: in.OrganizationID, Issuer: in.Issuer,
		ClientID: in.ClientID, ClientSecret: in.ClientSecret, Domains: in.Domains, DefaultRole: role,
	}
}

// CreateConnection stores a verified SSO connection.
func (s *Service) CreateConnection(ctx context.Context, in core.CreateSSOConnectionInput) (*core.SSOConnectionInfo, error) {
	if !s.Enabled() || !s.fresh(ctx, in.SessionToken) {
		return nil, core.ErrForbidden
	}
	for _, domain := range in.Domains {
		if s.deps.Config.SSO.VerifyDomain == nil || !s.deps.Config.SSO.VerifyDomain(ctx, in.OrganizationID, strings.ToLower(domain)) {
			s.emit(ctx, "sso_domain_unverified", in.OrganizationID, in.OrganizationID, "denied")
			return nil, core.ErrSSODomainNotVerified
		}
	}
	connection := fromCreate(in)
	if err := s.deps.Config.SSO.Connections.Create(ctx, connection); err != nil {
		return nil, err
	}
	s.emit(ctx, "sso_connection_created", in.OrganizationID, in.OrganizationID, "success")
	return &core.SSOConnectionInfo{
		ID: connection.ID, OrganizationID: connection.OrganizationID,
		Issuer: connection.Issuer, Domains: connection.Domains, DefaultRole: connection.DefaultRole,
	}, nil
}

// ListConnections returns safe connection views.
func (s *Service) ListConnections(ctx context.Context, sessionToken string) ([]*core.SSOConnectionInfo, error) {
	if !s.Enabled() || !s.fresh(ctx, sessionToken) {
		return nil, core.ErrForbidden
	}
	connections, err := s.deps.Config.SSO.Connections.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*core.SSOConnectionInfo, 0, len(connections))
	for _, c := range connections {
		out = append(out, &core.SSOConnectionInfo{
			ID: c.ID, OrganizationID: c.OrganizationID, Issuer: c.Issuer,
			Domains: c.Domains, DefaultRole: c.DefaultRole,
		})
	}
	return out, nil
}

// DeleteConnection removes a connection after a freshness check.
func (s *Service) DeleteConnection(ctx context.Context, id, sessionToken string) error {
	if !s.Enabled() || !s.fresh(ctx, sessionToken) {
		return core.ErrForbidden
	}
	if err := s.deps.Config.SSO.Connections.Delete(ctx, id); err != nil {
		return err
	}
	s.emit(ctx, "sso_connection_deleted", id, "", "success")
	return nil
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
			return nil, core.ErrSSODomainNotVerified
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
	sessionToken, err := s.deps.Sessions.Create(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	s.emit(ctx, "sso_sign_in", user.ID, "", "success")
	return &core.SSOCallbackResult{SessionToken: sessionToken, OrganizationID: connection.OrganizationID}, nil
}

func (s *Service) provision(ctx context.Context, identity *core.OAuthIdentity, connection *core.SSOConnection) (*core.User, error) {
	provider := "sso:" + connection.ID
	account, err := s.deps.Store.AccountByProvider(ctx, provider, identity.ProviderUserID)
	if err == nil {
		return s.deps.Store.UserByID(ctx, account.UserID)
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
