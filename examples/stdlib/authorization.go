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

// newAuthorizeIn returns Signet's built-in organization policy: member-add,
// member-remove and member-role go to the organization's owners and admins,
// re-reading membership on every check. Signet also installs this policy
// automatically when AuthorizeIn is unset; the example wires it explicitly so
// the seam stays visible.
func newAuthorizeIn(store signet.OrganizationStore) signet.AuthorizeIn {
	return signet.NewOrgAuthorizeIn(store)
}
