package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

// defaultOrgClient wires an OrganizationStore without AuthorizeIn, so the
// built-in owner/admin policy applies. The global authorizer only grants
// organization creation, mirroring the stdlib example minus its explicit
// AuthorizeIn.
func defaultOrgClient(t *testing.T) (*signet.Client, *fakeOrganizationStore, *testutil.Store) {
	t.Helper()
	orgStore := newFakeOrganizationStore()
	authStore := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.PathPrefix = "/auth"
	cfg.Store = authStore
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.OrganizationStore = orgStore
	cfg.Authorizer = signet.NewMemoryAuthorizer(
		signet.RoleStatements{"user": {signet.PermissionOrgsCreate}},
		func(context.Context, string) []string { return []string{"user"} },
	)
	// cfg.AuthorizeIn deliberately nil: the built-in org policy must apply.
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, orgStore, authStore
}

// The global Authorizer seam has no organization context, so with AuthorizeIn
// unset Signet must install its built-in policy: member-add, member-remove and
// member-role go to the organization's owners and admins. Otherwise owners
// could never manage members through the fallback.
func TestBuiltInOrgPolicyGrantsOwnerAndAdmin(t *testing.T) {
	client, _, _ := defaultOrgClient(t)
	ctx := context.Background()

	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "owner@example.com", Password: "correct horse", Name: "Owner"}); err != nil {
		t.Fatalf("SignUp owner: %v", err)
	}
	ownerCookies, ownerCSRF := signInSelfServe(t, client, "owner@example.com")
	orgID, _ := createSelfServeOrganization(t, client, ownerCookies, ownerCSRF)

	for _, email := range []string{"admin@example.com", "member@example.com", "outsider@example.com"} {
		if _, err := client.SignUp(ctx, signet.SignUpInput{Email: email, Password: "correct horse", Name: email}); err != nil {
			t.Fatalf("SignUp %s: %v", email, err)
		}
	}
	added := postSelfServe(t, client, "/organization-members/add",
		`{"organization_id":"`+orgID+`","email":"admin@example.com","role":"admin"}`, ownerCookies, ownerCSRF)
	if added.Code != http.StatusOK {
		t.Fatalf("owner add admin status = %d, body = %s", added.Code, added.Body.String())
	}
	addedMember := postSelfServe(t, client, "/organization-members/add",
		`{"organization_id":"`+orgID+`","email":"member@example.com","role":"member"}`, ownerCookies, ownerCSRF)
	if addedMember.Code != http.StatusOK {
		t.Fatalf("owner add member status = %d, body = %s", addedMember.Code, addedMember.Body.String())
	}

	adminCookies, adminCSRF := signInSelfServe(t, client, "admin@example.com")
	adminAdd := postSelfServe(t, client, "/organization-members/add",
		`{"organization_id":"`+orgID+`","email":"outsider@example.com","role":"member"}`, adminCookies, adminCSRF)
	if adminAdd.Code != http.StatusOK {
		t.Fatalf("admin add status = %d, body = %s", adminAdd.Code, adminAdd.Body.String())
	}
	adminRole := postSelfServe(t, client, "/organization-members/role",
		`{"organization_id":"`+orgID+`","email":"member@example.com","role":"admin"}`, adminCookies, adminCSRF)
	if adminRole.Code != http.StatusOK {
		t.Fatalf("admin role change status = %d, body = %s", adminRole.Code, adminRole.Body.String())
	}

	memberCookies, memberCSRF := signInSelfServe(t, client, "member@example.com")
	memberAdd := postSelfServe(t, client, "/organization-members/add",
		`{"organization_id":"`+orgID+`","email":"admin@example.com","role":"member"}`, memberCookies, memberCSRF)
	if memberAdd.Code != http.StatusForbidden || !strings.Contains(memberAdd.Body.String(), "forbidden") {
		t.Fatalf("member add status = %d, body = %s; want 403 forbidden", memberAdd.Code, memberAdd.Body.String())
	}
}

// A missing organization_id cannot be a permission question: it is a bad
// request. It must not answer with the generic 403 that a role denial or a
// stale session produces, because clients cannot tell the cases apart.
func TestOrganizationMemberMutationRequiresOrganizationID(t *testing.T) {
	store := newFakeOrganizationStore()
	client, _, _, cookies, csrf := selfServeClient(t, store)

	for _, tc := range []struct{ path, body string }{
		{"/organization-members/add", `{"email":"member@example.com","role":"member"}`},
		{"/organization-members/remove", `{"user_id":"member-1"}`},
		{"/organization-members/role", `{"user_id":"member-1","role":"admin"}`},
	} {
		rec := postSelfServe(t, client, tc.path, tc.body, cookies, csrf)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_input") {
			t.Fatalf("%s without organization_id status = %d, body = %s; want 400 invalid_input",
				tc.path, rec.Code, rec.Body.String())
		}
	}
	listed := getSelfServe(t, client, "/organization-members", cookies)
	if listed.Code != http.StatusBadRequest || !strings.Contains(listed.Body.String(), "invalid_input") {
		t.Fatalf("GET /organization-members without organization_id status = %d, body = %s; want 400 invalid_input",
			listed.Code, listed.Body.String())
	}
}

// The stale-session denial on guarded organization endpoints must say so:
// role-granted but stale returns 403 session_not_fresh, never the generic
// permission denied that a non-owner also receives.
func TestStaleSessionOnOrgEndpointIsDistinct(t *testing.T) {
	authStore := testutil.NewStore()
	client, _, _, cookies, csrf := selfServeClientWithStore(t, newFakeOrganizationStore(), authStore)
	orgID, _ := createSelfServeOrganization(t, client, cookies, csrf)

	freshAdd := postSelfServe(t, client, "/organization-members/add",
		fmt.Sprintf(`{"organization_id":%q,"user_id":"member-1","role":"member"}`, orgID), cookies, csrf)
	if freshAdd.Code != http.StatusOK {
		t.Fatalf("fresh owner add status = %d, body = %s", freshAdd.Code, freshAdd.Body.String())
	}

	for _, session := range authStore.Sessions {
		session.CreatedAt = time.Now().Add(-time.Hour)
	}
	staleRemove := postSelfServe(t, client, "/organization-members/remove",
		fmt.Sprintf(`{"organization_id":%q,"user_id":"member-1"}`, orgID), cookies, csrf)
	if staleRemove.Code != http.StatusForbidden || !strings.Contains(staleRemove.Body.String(), "session_not_fresh") {
		t.Fatalf("stale remove status = %d, body = %s; want 403 session_not_fresh",
			staleRemove.Code, staleRemove.Body.String())
	}
}
