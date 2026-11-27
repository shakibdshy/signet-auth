// Package orgadmin implements organizations and guarded admin management.
package orgadmin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/shakibdshy/signet-auth/internal/audit"
	"github.com/shakibdshy/signet-auth/internal/authorization"
	"github.com/shakibdshy/signet-auth/internal/core"
	"github.com/shakibdshy/signet-auth/internal/lastmethod"
	"github.com/shakibdshy/signet-auth/internal/secret"
	"github.com/shakibdshy/signet-auth/internal/session"
)

// Deps holds the dependencies shared by the organization and admin services.
type Deps struct {
	Config   *core.Config
	Store    core.Store
	Clock    core.Clock
	Sessions *session.Service
	Authz    *authorization.Service
	Logger   *slog.Logger
}

// Service implements organization and admin operations.
type Service struct {
	deps Deps
	imp  *lastmethod.Manager
}

// New returns a Service. impKey signs the one-hour impersonation cookie.
func New(deps Deps, impKey []byte) *Service {
	var imp *lastmethod.Manager
	if len(impKey) > 0 {
		imp = lastmethod.New(impKey, "signet_impersonation", time.Hour)
	}
	return &Service{deps: deps, imp: imp}
}

// fresh reports whether a raw Session token is within the freshness window.
func (s *Service) fresh(ctx context.Context, raw string) bool {
	if raw == "" {
		return false
	}
	fresh, err := s.deps.Sessions.IsFreshWithin(ctx, raw, s.deps.Config.Accounts.FreshWindow)
	return err == nil && fresh
}

// guard checks a permission and a fresh Session, auditing the denial.
func (s *Service) guard(ctx context.Context, actorID, sessionToken string, permission core.Permission) bool {
	if !s.deps.Authz.AuthorizePermission(ctx, actorID, permission) || !s.fresh(ctx, sessionToken) {
		audit.Emit(ctx, s.deps.Config.AuditSink, s.deps.Logger, core.AuditEvent{
			Name: audit.AuthorizationDenied, UserID: actorID, Outcome: "denied",
			Metadata: map[string]string{"permission": string(permission)},
		})
		return false
	}
	return true
}

// orgGuard checks membership, then the organization-aware permission seam.
func (s *Service) orgGuard(ctx context.Context, actorID, orgID, sessionToken string, permission core.Permission) bool {
	if _, err := s.deps.Config.OrganizationStore.MemberRole(ctx, orgID, actorID); err != nil {
		audit.Emit(ctx, s.deps.Config.AuditSink, s.deps.Logger, core.AuditEvent{
			Name: audit.AuthorizationDenied, UserID: actorID, Outcome: "denied",
			Metadata: map[string]string{"permission": string(permission), "organization_id": orgID},
		})
		return false
	}
	resource, action, _ := strings.Cut(string(permission), ":")
	var granted bool
	if s.deps.Config.AuthorizeIn != nil {
		granted = s.deps.Config.AuthorizeIn.AuthorizeIn(ctx, actorID, orgID, resource, action)
	} else {
		granted = s.deps.Authz.Authorize(ctx, actorID, resource, action)
	}
	if !granted || !s.fresh(ctx, sessionToken) {
		audit.Emit(ctx, s.deps.Config.AuditSink, s.deps.Logger, core.AuditEvent{
			Name: audit.AuthorizationDenied, UserID: actorID, Outcome: "denied",
			Metadata: map[string]string{"permission": string(permission), "organization_id": orgID},
		})
		return false
	}
	return true
}

func (s *Service) emit(ctx context.Context, name, actorID, targetID string) {
	audit.Emit(ctx, s.deps.Config.AuditSink, s.deps.Logger, core.AuditEvent{
		Name: name, UserID: actorID, Outcome: "success",
		Metadata: map[string]string{"target": targetID},
	})
}

// --- Organizations ---

// CreateOrganization creates an Organization owned by a User.
func (s *Service) CreateOrganization(ctx context.Context, in core.CreateOrganizationInput, sessionToken string) (*core.CreateOrganizationResult, error) {
	if s.deps.Config.OrganizationStore == nil || !s.guard(ctx, in.OwnerID, sessionToken, core.PermissionOrgsCreate) {
		return nil, core.ErrForbidden
	}
	org := &core.Organization{ID: secret.NewID(), OwnerID: in.OwnerID, Name: in.Name, CreatedAt: s.deps.Clock.Now()}
	if err := s.deps.Config.OrganizationStore.Create(ctx, org); err != nil {
		return nil, err
	}
	s.emit(ctx, audit.OrganizationCreated, in.OwnerID, org.ID)
	return &core.CreateOrganizationResult{Organization: org}, nil
}

// ListOrganizations returns a User's Organizations after checking the Session and grant.
func (s *Service) ListOrganizations(ctx context.Context, in core.ListOrganizationsInput, sessionToken string) (*core.ListOrganizationsResult, error) {
	if s.deps.Config.OrganizationStore == nil || !s.fresh(ctx, sessionToken) ||
		!s.deps.Authz.AuthorizePermission(ctx, in.UserID, core.PermissionOrgsCreate) {
		return nil, core.ErrForbidden
	}
	orgs, err := s.deps.Config.OrganizationStore.List(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	return &core.ListOrganizationsResult{Organizations: orgs}, nil
}

// AddOrganizationMember adds a Member after an org-scoped check.
func (s *Service) AddOrganizationMember(ctx context.Context, in core.AddOrganizationMemberInput, sessionToken string) error {
	email := core.NormalizeEmail(in.Email)
	hasID, hasEmail := in.UserID != "", email != ""
	if hasID == hasEmail {
		return core.ErrInvalidMemberInput
	}
	if hasEmail {
		user, err := s.deps.Store.UserByEmail(ctx, email)
		if errors.Is(err, core.ErrNotFound) {
			return core.ErrUserNotFound
		}
		if err != nil {
			return err
		}
		in.UserID = user.ID
	}
	if s.deps.Config.OrganizationStore == nil ||
		!s.orgGuard(ctx, in.ActorID, in.OrgID, sessionToken, core.PermissionOrgsMemberAdd) {
		return core.ErrForbidden
	}
	if err := s.deps.Config.OrganizationStore.AddMember(ctx, in.OrgID, in.UserID, in.Role); err != nil {
		return err
	}
	s.emit(ctx, audit.OrganizationMemberAdded, in.ActorID, in.UserID)
	return nil
}

// RemoveOrganizationMember removes a Member after an org-scoped check.
func (s *Service) RemoveOrganizationMember(ctx context.Context, orgID, userID, actorID, sessionToken string) error {
	if s.deps.Config.OrganizationStore == nil ||
		!s.orgGuard(ctx, actorID, orgID, sessionToken, core.PermissionOrgsMemberRemove) {
		return core.ErrForbidden
	}
	if err := s.deps.Config.OrganizationStore.RemoveMember(ctx, orgID, userID); err != nil {
		return err
	}
	s.emit(ctx, audit.OrganizationMemberRemoved, actorID, userID)
	return nil
}

// SetOrganizationMemberRole changes a Member's role after an org-scoped check.
func (s *Service) SetOrganizationMemberRole(ctx context.Context, orgID, userID, role, actorID, sessionToken string) error {
	if s.deps.Config.OrganizationStore == nil ||
		!s.orgGuard(ctx, actorID, orgID, sessionToken, core.PermissionOrgsMemberRole) {
		return core.ErrForbidden
	}
	if err := s.deps.Config.OrganizationStore.SetMemberRole(ctx, orgID, userID, role); err != nil {
		return err
	}
	s.emit(ctx, audit.OrganizationMemberRoleSet, actorID, userID)
	return nil
}

// ListOrganizationMembers returns an Organization's Members after an org-scoped check.
func (s *Service) ListOrganizationMembers(ctx context.Context, orgID, userID, sessionToken string) (*core.ListOrganizationMembersResult, error) {
	if s.deps.Config.OrganizationStore == nil ||
		!s.orgGuard(ctx, userID, orgID, sessionToken, core.PermissionOrgsMemberAdd) {
		return nil, core.ErrForbidden
	}
	members, err := s.deps.Config.OrganizationStore.Members(ctx, orgID)
	if err != nil {
		return nil, err
	}
	return &core.ListOrganizationMembersResult{Members: members}, nil
}

// SetActiveOrganization verifies membership before the caller writes the cookie.
func (s *Service) SetActiveOrganization(ctx context.Context, orgID, userID, sessionToken string) error {
	if s.deps.Config.OrganizationStore == nil || !s.fresh(ctx, sessionToken) {
		return core.ErrForbidden
	}
	if _, err := s.deps.Config.OrganizationStore.MemberRole(ctx, orgID, userID); err != nil {
		return core.ErrForbidden
	}
	return nil
}

// --- Admin management ---

// ListUsers returns safe User fields after a Session and grant check.
func (s *Service) ListUsers(ctx context.Context, actorID, sessionToken string) (*core.AdminListUsersResult, error) {
	if s.deps.Config.AdminUserStore == nil || !s.fresh(ctx, sessionToken) ||
		!s.deps.Authz.AuthorizePermission(ctx, actorID, core.PermissionUsersBan) {
		return nil, core.ErrForbidden
	}
	all, err := s.deps.Config.AdminUserStore.ListUsersForAdmin(ctx)
	if err != nil {
		return nil, err
	}
	users := make([]*core.UserInfo, 0, len(all))
	for _, user := range all {
		users = append(users, &core.UserInfo{ID: user.ID, Email: user.Email, Name: user.Name, Disabled: user.Disabled})
	}
	return &core.AdminListUsersResult{Users: users}, nil
}

// BanUser disables a User account.
func (s *Service) BanUser(ctx context.Context, in core.BanUserInput) error {
	if in.ActorID == in.UserID || !s.guard(ctx, in.ActorID, in.SessionToken, core.PermissionUsersBan) {
		return core.ErrForbidden
	}
	user, err := s.deps.Store.UserByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	user.Disabled = true
	if err := s.deps.Store.UpdateUser(ctx, user); err != nil {
		return err
	}
	s.emit(ctx, audit.UserBanned, in.ActorID, in.UserID)
	return nil
}

// UnbanUser re-enables a User account.
func (s *Service) UnbanUser(ctx context.Context, in core.UnbanUserInput) error {
	if !s.guard(ctx, in.ActorID, in.SessionToken, core.PermissionUsersBan) {
		return core.ErrForbidden
	}
	user, err := s.deps.Store.UserByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	user.Disabled = false
	if err := s.deps.Store.UpdateUser(ctx, user); err != nil {
		return err
	}
	s.emit(ctx, audit.UserUnbanned, in.ActorID, in.UserID)
	return nil
}

// SetUserRole writes global roles for a User.
func (s *Service) SetUserRole(ctx context.Context, in core.AdminSetUserRoleInput) error {
	if !s.guard(ctx, in.ActorID, in.SessionToken, core.PermissionUsersSetRole) || s.deps.Config.RoleWriter == nil {
		return core.ErrForbidden
	}
	if err := s.deps.Config.RoleWriter.SetRoles(ctx, in.UserID, in.Roles); err != nil {
		return err
	}
	s.emit(ctx, audit.UserRolesSet, in.ActorID, in.UserID)
	return nil
}

// ListUserSessions returns a User's Sessions after a Session and grant check.
func (s *Service) ListUserSessions(ctx context.Context, actorID, userID, sessionToken string) (*core.ListSessionsResult, error) {
	if !s.fresh(ctx, sessionToken) || !s.deps.Authz.AuthorizePermission(ctx, actorID, core.PermissionSessionsRevoke) {
		return nil, core.ErrForbidden
	}
	sessions, err := s.deps.Sessions.List(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &core.ListSessionsResult{Sessions: sessions}, nil
}

// RevokeUserSession revokes one Session after a freshness and grant check.
func (s *Service) RevokeUserSession(ctx context.Context, actorID, sessionID, sessionToken string) error {
	if !s.guard(ctx, actorID, sessionToken, core.PermissionSessionsRevoke) {
		return core.ErrForbidden
	}
	if err := s.deps.Sessions.Revoke(ctx, sessionID); err != nil {
		return err
	}
	s.emit(ctx, audit.UserSessionRevoked, actorID, sessionID)
	return nil
}

type impersonationPayload struct {
	AdminID       string `json:"admin_id"`
	OriginalToken string `json:"original_token"`
}

// ImpersonateUser creates a fresh Store-backed Session for the target.
func (s *Service) ImpersonateUser(ctx context.Context, in core.ImpersonateUserInput) (*core.ImpersonationResult, error) {
	if in.ActorID == in.UserID || s.imp == nil ||
		!s.guard(ctx, in.ActorID, in.SessionToken, core.PermissionUsersImpersonate) {
		return nil, core.ErrForbidden
	}
	tempToken, err := s.deps.Sessions.Create(ctx, in.UserID, in.UserAgent)
	if err != nil {
		return nil, err
	}
	s.emit(ctx, audit.UserImpersonated, in.ActorID, in.UserID)
	return &core.ImpersonationResult{Token: tempToken, AdminID: in.ActorID}, nil
}

// ImpersonationFromRequest returns the admin ID and original Session token from a signed cookie.
func (s *Service) ImpersonationFromRequest(r *http.Request) (adminID, originalToken string) {
	if s.imp == nil {
		return "", ""
	}
	raw := s.imp.Method(r)
	if raw == "" {
		return "", ""
	}
	var payload impersonationPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil || payload.AdminID == "" {
		return "", ""
	}
	return payload.AdminID, payload.OriginalToken
}

// SetImpersonationCookie writes the signed cookie carrying the admin and original token.
func (s *Service) SetImpersonationCookie(w http.ResponseWriter, adminID, originalToken string) {
	if s.imp == nil {
		return
	}
	payload, err := json.Marshal(impersonationPayload{AdminID: adminID, OriginalToken: originalToken})
	if err != nil {
		return
	}
	s.imp.SetCookie(w, string(payload))
}

// ClearImpersonationCookie expires the impersonation cookie.
func (s *Service) ClearImpersonationCookie(w http.ResponseWriter) {
	if s.imp != nil {
		s.imp.Clear(w)
	}
}

// StopImpersonating revokes the temporary Session and restores the original token.
func (s *Service) StopImpersonating(ctx context.Context, in core.StopImpersonatingInput) (originalToken string, err error) {
	if in.Token == "" {
		return "", core.ErrTokenInvalid
	}
	session, err := s.deps.Store.SessionByHash(ctx, secret.Digest(in.Token))
	if err != nil {
		return "", core.ErrTokenInvalid
	}
	if err := s.deps.Sessions.Revoke(ctx, session.ID); err != nil {
		return "", err
	}
	s.emit(ctx, audit.ImpersonationStopped, in.AdminID, "")
	return in.OriginalToken, nil
}

// IsImpersonating reports whether a request carries a signed impersonation cookie.
func (s *Service) IsImpersonating(r *http.Request) bool {
	adminID, _ := s.ImpersonationFromRequest(r)
	return adminID != ""
}

// AdminActor returns the administrator ID for a request, or the supplied ID.
func (s *Service) AdminActor(r *http.Request, fallback string) string {
	if adminID, _ := s.ImpersonationFromRequest(r); adminID != "" {
		return adminID
	}
	return fallback
}
