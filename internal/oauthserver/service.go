// Package oauthserver implements Signet's opt-in Authorization server.
package oauthserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/shakibdshy/signet/internal/audit"
	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
	"github.com/shakibdshy/signet/internal/token"
)

// Service implements the Authorization server operations.
type Service struct {
	cfg     *core.Config
	tokens  *token.Service
	jwt     *token.JWTService
	logger  *slog.Logger
	resolve func(context.Context, string) (*core.User, error)
}

// New returns a Service bound to the resolved config.
func New(cfg *core.Config, tokens *token.Service, jwt *token.JWTService, logger *slog.Logger, resolve func(context.Context, string) (*core.User, error)) *Service {
	return &Service{cfg: cfg, tokens: tokens, jwt: jwt, logger: logger, resolve: resolve}
}

// Enabled reports whether the Authorization server is configured.
func (s *Service) Enabled() bool {
	return s.cfg.AuthorizationServer != nil && s.jwt != nil
}

func (s *Service) client(ctx context.Context, id string) (*core.OAuthClient, error) {
	if s.cfg.AuthorizationServer.Clients != nil {
		client, err := s.cfg.AuthorizationServer.Clients.Get(ctx, id)
		if err == nil {
			return client, nil
		}
	}
	for i := range s.cfg.AuthorizationServer.StaticClients {
		if s.cfg.AuthorizationServer.StaticClients[i].ID == id {
			return &s.cfg.AuthorizationServer.StaticClients[i], nil
		}
	}
	return nil, core.ErrNotFound
}

func (s *Service) trusted(ctx context.Context, id string) bool {
	if s.cfg.AuthorizationServer.Clients != nil {
		if trusted, err := s.cfg.AuthorizationServer.Clients.IsTrusted(ctx, id); err == nil {
			return trusted
		}
	}
	client, err := s.client(ctx, id)
	return err == nil && client.Trusted
}

func (s *Service) redirects(ctx context.Context, client *core.OAuthClient) []string {
	if s.cfg.AuthorizationServer.Clients != nil {
		if list, err := s.cfg.AuthorizationServer.Clients.AllowedRedirects(ctx, client.ID); err == nil {
			return list
		}
	}
	return client.RedirectURIs
}

func (s *Service) scopes(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, core.ErrForbidden
	}
	allowed := map[string]bool{
		string(core.OAuthScopeOpenID): true, string(core.OAuthScopeProfile): true,
		string(core.OAuthScopeEmail): true, string(core.OAuthScopeOffline): true,
	}
	for _, scope := range strings.Fields(raw) {
		if !allowed[scope] {
			return nil, core.ErrForbidden
		}
	}
	return strings.Fields(raw), nil
}

func (s *Service) audience(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	for _, allowed := range s.cfg.AuthorizationServer.Audiences {
		if raw == allowed {
			return raw, nil
		}
	}
	return "", core.ErrForbidden
}

// Authorize validates a request and issues an authorization code.
func (s *Service) Authorize(ctx context.Context, in core.OAuthAuthorizeInput) (*core.OAuthAuthorizeResult, error) {
	if s.resolve != nil && in.UserID == "" {
		if user, err := s.resolve(ctx, in.SessionToken); err == nil && user != nil {
			in.UserID = user.ID
		}
	}
	if !s.Enabled() || in.UserID == "" || in.ResponseType != "code" {
		return nil, core.ErrForbidden
	}
	client, err := s.client(ctx, in.ClientID)
	if err != nil {
		return nil, core.ErrForbidden
	}
	allowed := false
	for _, uri := range s.redirects(ctx, client) {
		if uri == in.RedirectURI {
			allowed = true
		}
	}
	if !allowed || in.CodeChallenge == "" {
		return nil, core.ErrForbidden
	}
	scopes, err := s.scopes(in.Scope)
	if err != nil {
		return nil, err
	}
	audience, err := s.audience(in.Audience)
	if err != nil {
		return nil, err
	}
	if !s.trusted(ctx, client.ID) {
		if s.cfg.AuthorizationServer.Consent != nil &&
			!s.cfg.AuthorizationServer.Consent(ctx, client.ID, in.UserID, scopes) {
			s.emit(ctx, "oauth_consent_denied", in.UserID, client.ID, "denied")
			return nil, core.ErrForbidden
		}
	}
	data, _ := json.Marshal(struct {
		ClientID    string   `json:"client_id"`
		RedirectURI string   `json:"redirect_uri"`
		Challenge   string   `json:"challenge"`
		Scopes      []string `json:"scopes"`
		Audience    string   `json:"audience"`
		UserID      string   `json:"user_id"`
	}{client.ID, in.RedirectURI, in.CodeChallenge, scopes, audience, in.UserID})
	code, _, err := s.tokens.IssueWithData(ctx, in.UserID, core.TokenOAuthState, 5*time.Minute, string(data))
	if err != nil {
		return nil, err
	}
	s.emit(ctx, "oauth_code_issued", in.UserID, client.ID, "success")
	return &core.OAuthAuthorizeResult{Code: code, State: in.State}, nil
}

// Exchange redeems an authorization code for tokens.
func (s *Service) Exchange(ctx context.Context, in core.OAuthTokenInput) (*core.OAuthTokenResult, error) {
	if !s.Enabled() || in.GrantType != "authorization_code" {
		return nil, core.ErrForbidden
	}
	if _, err := s.tokens.Consume(ctx, core.TokenOAuthState, in.Code); err != nil {
		return nil, core.ErrTokenInvalid
	}
	var data struct {
		ClientID    string   `json:"client_id"`
		RedirectURI string   `json:"redirect_uri"`
		Challenge   string   `json:"challenge"`
		Scopes      []string `json:"scopes"`
		Audience    string   `json:"audience"`
		UserID      string   `json:"user_id"`
	}
	raw, err := token.ParseData(in.Code)
	if err != nil || json.Unmarshal([]byte(raw), &data) != nil {
		return nil, core.ErrTokenInvalid
	}
	if data.ClientID != in.ClientID || data.RedirectURI == "" {
		return nil, core.ErrTokenInvalid
	}
	sum := sha256.Sum256([]byte(in.CodeVerifier))
	if data.Challenge != base64.RawURLEncoding.EncodeToString(sum[:]) {
		return nil, core.ErrTokenInvalid
	}
	pair, err := s.jwt.IssueWithScope(ctx, data.UserID, data.Audience, data.Scopes)
	if err != nil {
		return nil, err
	}
	s.emit(ctx, "oauth_token_issued", data.UserID, data.ClientID, "success")
	return &core.OAuthTokenResult{
		AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken,
		TokenType: "Bearer", ExpiresIn: pair.ExpiresIn, Scope: strings.Join(data.Scopes, " "),
	}, nil
}

// Refresh rotates a Refresh token, preserving its scopes and audience.
func (s *Service) Refresh(ctx context.Context, in core.OAuthTokenInput) (*core.OAuthTokenResult, error) {
	if !s.Enabled() || in.GrantType != "refresh_token" || in.RefreshToken == "" {
		return nil, core.ErrForbidden
	}
	pair, err := s.jwt.RefreshWithScope(ctx, in.RefreshToken)
	if err != nil {
		return nil, err
	}
	claims, _ := parseScope(in.RefreshToken)
	return &core.OAuthTokenResult{
		AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken,
		TokenType: "Bearer", ExpiresIn: pair.ExpiresIn, Scope: strings.Join(claims, " "),
	}, nil
}

func parseScope(raw string) ([]string, error) {
	data, err := token.ParseData(raw)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		return nil, err
	}
	return parsed.Scopes, nil
}

// BeginDevice starts a Device authorization.
func (s *Service) BeginDevice(ctx context.Context, in core.DeviceAuthorizeInput) (*core.DeviceAuthorizeResult, error) {
	if !s.Enabled() || s.cfg.AuthorizationServer.Devices == nil {
		return nil, core.ErrForbidden
	}
	client, err := s.client(ctx, in.ClientID)
	if err != nil {
		return nil, core.ErrForbidden
	}
	if _, err := s.scopes(in.Scope); err != nil {
		return nil, err
	}
	if _, err := s.audience(in.Audience); err != nil {
		return nil, err
	}
	now := s.cfg.Clock.Now()
	ttl := s.cfg.AuthorizationServer.DeviceTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	authorization := &core.DeviceAuthorization{
		DeviceCode: secret.NewToken(), UserCode: userCode(), ClientID: client.ID,
		Scopes: strings.Fields(in.Scope), ExpiresAt: now.Add(ttl), CreatedAt: now,
	}
	if err := s.cfg.AuthorizationServer.Devices.Create(ctx, authorization); err != nil {
		return nil, err
	}
	return &core.DeviceAuthorizeResult{
		DeviceCode: authorization.DeviceCode, UserCode: authorization.UserCode,
		VerificationURL: s.cfg.AppURL + strings.TrimRight(s.cfg.PathPrefix, "/") + "/oauth/device/approve",
		ExpiresIn:       int64(ttl / time.Second),
	}, nil
}

// ApproveDevice records a User's approval from an authenticated Session.
func (s *Service) ApproveDevice(ctx context.Context, in core.DeviceApproveInput) error {
	if s.resolve != nil && in.UserID == "" {
		if user, err := s.resolve(ctx, in.SessionToken); err == nil && user != nil {
			in.UserID = user.ID
		}
	}
	if !s.Enabled() || s.cfg.AuthorizationServer.Devices == nil || in.UserID == "" {
		return core.ErrForbidden
	}
	device, err := s.cfg.AuthorizationServer.Devices.ByUserCode(ctx, strings.ToUpper(in.UserCode))
	if err != nil || !s.cfg.Clock.Now().Before(device.ExpiresAt) || device.Approved {
		return core.ErrTokenInvalid
	}
	if err := s.cfg.AuthorizationServer.Devices.Approve(ctx, device.UserCode, in.UserID); err != nil {
		return err
	}
	s.emit(ctx, "oauth_device_approved", in.UserID, device.ClientID, "success")
	return nil
}

// DeviceToken polls for tokens after approval.
func (s *Service) DeviceToken(ctx context.Context, deviceCode string) (*core.OAuthTokenResult, error) {
	if !s.Enabled() || s.cfg.AuthorizationServer.Devices == nil {
		return nil, core.ErrForbidden
	}
	device, err := s.cfg.AuthorizationServer.Devices.ByDeviceCode(ctx, deviceCode)
	if err != nil {
		return nil, core.ErrTokenInvalid
	}
	if !s.cfg.Clock.Now().Before(device.ExpiresAt) {
		return nil, core.ErrTokenExpired
	}
	if !device.Approved || device.UserID == "" {
		return nil, core.ErrForbidden
	}
	pair, err := s.jwt.IssueWithScope(ctx, device.UserID, "", device.Scopes)
	if err != nil {
		return nil, err
	}
	s.emit(ctx, "oauth_token_issued", device.UserID, device.ClientID, "success")
	return &core.OAuthTokenResult{
		AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken,
		TokenType: "Bearer", ExpiresIn: pair.ExpiresIn, Scope: strings.Join(device.Scopes, " "),
	}, nil
}

func userCode() string {
	sum := sha256.Sum256([]byte(secret.NewToken()))
	return strings.ToUpper(hex.EncodeToString(sum[:4]))[:4] + "-" + strings.ToUpper(hex.EncodeToString(sum[4:8]))[:4]
}

// VerifyPKCE is exposed for contract tests that check S256 behaviour.
func VerifyPKCE(challenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return hmac.Equal([]byte(challenge), []byte(base64.RawURLEncoding.EncodeToString(sum[:])))
}

func (s *Service) emit(ctx context.Context, name, userID, clientID, outcome string) {
	audit.Emit(ctx, s.cfg.AuditSink, s.logger, core.AuditEvent{
		Name: name, UserID: userID, Outcome: outcome,
		Metadata: map[string]string{"client_id": clientID},
	})
}
