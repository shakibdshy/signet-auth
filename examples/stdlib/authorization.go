package main

import (
	"context"

	"github.com/shakibdshy/signet-auth"
)

// newAuthorizer grants only organization creation to the ordinary user role.
// Every other permission — including all admin and system permissions —
// remains ungranted, so those routes stay deny-by-default.
func newAuthorizer() signet.Authorizer {
	return signet.NewMemoryAuthorizer(
		signet.RoleStatements{"user": {signet.PermissionOrgsCreate}},
		func(context.Context, string) []string { return []string{"user"} },
	)
}

type orgAuthorizeIn struct {
	store signet.OrganizationStore
}

var _ signet.AuthorizeIn = (*orgAuthorizeIn)(nil)

// newAuthorizeIn builds an organization-scoped policy that reads membership
// from the store on every check. It grants member mutations to owners and
// admins only, and never falls back to the global authorizer.
func newAuthorizeIn(store signet.OrganizationStore) signet.AuthorizeIn {
	return &orgAuthorizeIn{store: store}
}

func (a *orgAuthorizeIn) AuthorizeIn(ctx context.Context, userID, orgID, resource, action string) bool {
	if resource != "organizations" {
		return false
	}
	switch action {
	case "member-add", "member-remove", "member-role":
	default:
		return false
	}
	role, err := a.store.MemberRole(ctx, orgID, userID)
	if err != nil {
		return false
	}
	return role == "owner" || role == "admin"
}
