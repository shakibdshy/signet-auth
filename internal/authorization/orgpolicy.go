package authorization

import (
	"context"
	"slices"

	"github.com/shakibdshy/signet-auth/internal/core"
)

// defaultOrgManagerRoles are the membership roles the built-in organization
// policy grants member management to when the application does not name its
// own.
var defaultOrgManagerRoles = []string{"owner", "admin"}

// orgRolePolicy is the built-in AuthorizeIn: it grants organization member
// management to members holding one of the configured membership roles by
// re-reading membership from the OrganizationStore on every check. It exists
// because the global Authorizer seam has no organization context and could
// never see org roles.
type orgRolePolicy struct {
	store core.OrganizationStore
	roles []string
}

// NewOrgAuthorizeIn returns the built-in organization policy. Signet installs
// it automatically when Config.OrganizationStore is set and Config.AuthorizeIn
// is not; applications may also wire it explicitly. The optional managerRoles
// name the membership roles that manage members; empty selects the default,
// the organization's owner and admin roles.
func NewOrgAuthorizeIn(store core.OrganizationStore, managerRoles ...string) core.AuthorizeIn {
	roles := managerRoles
	if len(roles) == 0 {
		roles = defaultOrgManagerRoles
	}
	return &orgRolePolicy{store: store, roles: roles}
}

func (p *orgRolePolicy) AuthorizeIn(ctx context.Context, userID, orgID, resource, action string) bool {
	if resource != "organizations" {
		return false
	}
	switch action {
	case "member-add", "member-remove", "member-role":
	default:
		return false
	}
	role, err := p.store.MemberRole(ctx, orgID, userID)
	if err != nil {
		return false
	}
	return slices.Contains(p.roles, role)
}
