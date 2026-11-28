package tests

import (
	"context"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
	"github.com/shakibdshy/signet-auth/store/conformance"
)

// The organization store contracts ship conformance suites so that
// application-owned implementations can verify the semantics the library's
// organization and admin features depend on. The fakes below are themselves
// checked against them.
func TestOrganizationStoreConformance(t *testing.T) {
	conformance.RunOrganizations(t, func(_ *testing.T) signet.OrganizationStore {
		return newFakeOrganizationStore()
	})
}

func TestAdminUserStoreConformance(t *testing.T) {
	conformance.RunAdminUsers(t, func(_ *testing.T) (signet.AdminUserStore, func(context.Context, *signet.User) error) {
		store := testutil.NewStore()
		return store, store.CreateUser
	})
}
