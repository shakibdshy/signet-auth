package authorization

import (
	"context"

	"github.com/shakibdshy/signet-auth/internal/core"
)

// orgRolePolicy is the built-in AuthorizeIn: it grants organization member
// management to the organization's owners and admins by re-reading membership
// from the OrganizationStore on every check. It exists because the global
// Authorizer seam has no organization context and could never see org roles.
type orgRolePolicy struct {
	store core.OrganizationStore
}

// NewOrgAuthorizeIn returns the built-in organization policy. Signet installs
// it automatically when Config.OrganizationStore is set and Config.AuthorizeIn
// is not; applications may also wire it explicitly.
func NewOrgAuthorizeIn(store core.OrganizationStore) core.AuthorizeIn {
	return &orgRolePolicy{store: store}
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
	return role == "owner" || role == "admin"
}
