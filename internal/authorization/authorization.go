// Package authorization implements opt-in roles, permissions and API keys.
package authorization

import (
	"context"
	"log/slog"
	"strings"

	"github.com/shakibdshy/signet/internal/audit"
	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
)

// MemoryConfig configures the built-in in-memory Authorizer.
type MemoryConfig struct {
	Statements map[string][]string
	Roles      func(context.Context, string) []string
}

// MemoryAuthorizer resolves roles through a callback and checks them against
// configured role statements. It is immutable after construction.
type MemoryAuthorizer struct {
	statements map[string][]string
	roles      func(context.Context, string) []string
}

// NewMemoryAuthorizer returns an Authorizer from role statements and a roles callback.
func NewMemoryAuthorizer(cfg MemoryConfig) *MemoryAuthorizer {
	statements := make(map[string][]string, len(cfg.Statements))
	for role, permissions := range cfg.Statements {
		statements[role] = append([]string(nil), permissions...)
	}
	roles := cfg.Roles
	if roles == nil {
		roles = func(context.Context, string) []string { return nil }
	}
	return &MemoryAuthorizer{statements: statements, roles: roles}
}

// Roles returns a User's roles from the application callback.
func (a *MemoryAuthorizer) Roles(ctx context.Context, userID string) []string {
	return a.roles(ctx, userID)
}

// Authorize reports whether any of a User's roles grants resource:action.
func (a *MemoryAuthorizer) Authorize(ctx context.Context, userID, resource, action string) bool {
	wanted := resource + ":" + action
	for _, role := range a.Roles(ctx, userID) {
		for _, permission := range a.statements[role] {
			if permission == wanted {
				return true
			}
		}
	}
	return false
}

// Service holds the authorization dependencies and implements the façade operations.
type Service struct {
	cfg    *core.Config
	clock  core.Clock
	logger *slog.Logger
	fresh  func(context.Context, string) bool
}

// NewService returns a Service bound to the resolved config. fresh reports
// whether a raw session token is within the configured freshness window.
func NewService(cfg *core.Config, clock core.Clock, logger *slog.Logger, fresh func(context.Context, string) bool) *Service {
	if fresh == nil {
		fresh = func(context.Context, string) bool { return false }
	}
	return &Service{cfg: cfg, clock: clock, logger: logger, fresh: fresh}
}

// Authorize reports whether a User holds a permission and audits denials.
func (s *Service) Authorize(ctx context.Context, userID, resource, action string) bool {
	if s.cfg.Authorizer == nil {
		return false
	}
	if s.cfg.Authorizer.Authorize(ctx, userID, resource, action) {
		return true
	}
	audit.Emit(ctx, s.cfg.AuditSink, s.logger, core.AuditEvent{
		Name: audit.AuthorizationDenied, UserID: userID, Outcome: "denied",
		Metadata: map[string]string{"permission": resource + ":" + action},
	})
	return false
}

// AuthorizePermission splits a published permission and checks it.
func (s *Service) AuthorizePermission(ctx context.Context, userID string, permission core.Permission) bool {
	resource, action, ok := strings.Cut(string(permission), ":")
	if !ok {
		return false
	}
	return s.Authorize(ctx, userID, resource, action)
}

// CreateAPIKey issues a digest-only API key.
func (s *Service) CreateAPIKey(ctx context.Context, in core.CreateAPIKeyInput) (*core.CreateAPIKeyResult, error) {
	if s.cfg.APIKeyStore == nil {
		return nil, core.ErrForbidden
	}
	owner := in.OwnerUserID
	if owner == "" {
		owner = core.SystemOwnerID
	}
	if !s.AuthorizePermission(ctx, owner, core.PermissionAPIKeysCreate) || !s.fresh(ctx, in.SessionToken) {
		return nil, core.ErrForbidden
	}
	raw := secret.NewToken()
	digest := secret.Digest(raw)
	key := &core.APIKey{
		ID: secret.NewID(), OwnerUserID: owner, Name: in.Name,
		Hash: digest, Prefix: digest[:6], Roles: in.Roles,
		Remaining: in.Remaining, ExpiresAt: in.ExpiresAt, CreatedAt: s.clock.Now(),
	}
	if err := s.cfg.APIKeyStore.Create(ctx, key); err != nil {
		return nil, err
	}
	audit.Emit(ctx, s.cfg.AuditSink, s.logger, core.AuditEvent{
		Name: audit.APIKeyCreated, UserID: owner, Outcome: "success",
		Metadata: map[string]string{"key_id": key.ID},
	})
	return &core.CreateAPIKeyResult{Raw: raw, Key: key}, nil
}

// VerifyAPIKey atomically consumes one use of an API key.
func (s *Service) VerifyAPIKey(ctx context.Context, raw string) (*core.Principal, error) {
	if s.cfg.APIKeyStore == nil {
		return nil, core.ErrForbidden
	}
	key, err := s.cfg.APIKeyStore.ConsumeAPIKey(ctx, secret.Digest(raw))
	if err != nil {
		return nil, core.ErrTokenInvalid
	}
	return &core.Principal{OwnerUserID: key.OwnerUserID, Roles: key.Roles}, nil
}

// ListAPIKeys returns a User's API keys.
func (s *Service) ListAPIKeys(ctx context.Context, in core.ListAPIKeysInput) (*core.ListAPIKeysResult, error) {
	if s.cfg.APIKeyStore == nil || !s.AuthorizePermission(ctx, in.OwnerUserID, core.PermissionAPIKeysRevoke) {
		return nil, core.ErrForbidden
	}
	keys, err := s.cfg.APIKeyStore.List(ctx, in.OwnerUserID)
	if err != nil {
		return nil, err
	}
	return &core.ListAPIKeysResult{Keys: keys}, nil
}

// RevokeAPIKey revokes one of a User's API keys.
func (s *Service) RevokeAPIKey(ctx context.Context, in core.RevokeAPIKeyInput) error {
	if s.cfg.APIKeyStore == nil || !s.AuthorizePermission(ctx, in.OwnerUserID, core.PermissionAPIKeysRevoke) || !s.fresh(ctx, in.SessionToken) {
		return core.ErrForbidden
	}
	keys, err := s.cfg.APIKeyStore.List(ctx, in.OwnerUserID)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if key.ID == in.ID {
			if err := s.cfg.APIKeyStore.Revoke(ctx, in.ID); err != nil {
				return err
			}
			audit.Emit(ctx, s.cfg.AuditSink, s.logger, core.AuditEvent{
				Name: audit.APIKeyRevoked, UserID: in.OwnerUserID, Outcome: "success",
				Metadata: map[string]string{"key_id": in.ID},
			})
			return nil
		}
	}
	return core.ErrForbidden
}

// SetRoles writes global roles through the RoleWriter.
func (s *Service) SetRoles(ctx context.Context, userID string, roles []string) error {
	if s.cfg.RoleWriter == nil || !s.AuthorizePermission(ctx, userID, core.PermissionUsersSetRole) {
		return core.ErrForbidden
	}
	return s.cfg.RoleWriter.SetRoles(ctx, userID, roles)
}
