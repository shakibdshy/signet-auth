package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

type selfServeAuthorizeIn struct {
	store signet.OrganizationStore
}

var _ signet.AuthorizeIn = (*selfServeAuthorizeIn)(nil)

func (a *selfServeAuthorizeIn) AuthorizeIn(ctx context.Context, userID, orgID, resource, action string) bool {
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

// selfServeClient mirrors the stdlib example's authorization wiring: a real
// memory authorizer granting only organizations:create, plus an org-scoped
// policy that re-reads membership. It returns the sign-in cookies and CSRF
// token paired with the owner's session.
func selfServeClient(t *testing.T, store *fakeOrganizationStore) (*signet.Client, *fakeOrganizationStore, string, []*http.Cookie, string) {
	t.Helper()
	return selfServeClientWithStore(t, store, testutil.NewStore())
}

func selfServeClientWithStore(t *testing.T, store *fakeOrganizationStore, authStore *testutil.Store) (*signet.Client, *fakeOrganizationStore, string, []*http.Cookie, string) {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.PathPrefix = "/auth"
	cfg.Store = authStore
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.OrganizationStore = store
	cfg.Authorizer = signet.NewMemoryAuthorizer(
		signet.RoleStatements{"user": {signet.PermissionOrgsCreate}},
		func(context.Context, string) []string { return []string{"user"} },
	)
	cfg.AuthorizeIn = &selfServeAuthorizeIn{store: store}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	signUp, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "owner@example.com", Password: "correct horse", Name: "Owner",
	})
	if err != nil {
		t.Fatalf("SignUp owner: %v", err)
	}
	cookies, csrf := signInSelfServe(t, client, "owner@example.com")
	return client, store, signUp.User.ID, cookies, csrf
}

func postSelfServe(t *testing.T, client *signet.Client, path, body string, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth"+path, strings.NewReader(body))
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	return rec
}

func getSelfServe(t *testing.T, client *signet.Client, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth"+path, nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	return rec
}

func signInSelfServe(t *testing.T, client *signet.Client, email string) ([]*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/signin",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":"correct horse"}`, email)))
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign-in %s = %d, body %s", email, rec.Code, rec.Body.String())
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.CSRFToken == "" {
		t.Fatalf("sign-in body = %s, err = %v", rec.Body.String(), err)
	}
	return rec.Result().Cookies(), body.CSRFToken
}

func createSelfServeOrganization(t *testing.T, client *signet.Client, cookies []*http.Cookie, csrf string) (string, []byte) {
	t.Helper()
	created := postSelfServe(t, client, "/organizations", `{"name":"Acme"}`, cookies, csrf)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", created.Code, created.Body.String())
	}
	var result struct {
		Organization struct {
			ID string `json:"id"`
		} `json:"Organization"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || result.Organization.ID == "" {
		t.Fatalf("decode create = %v, body = %s", err, created.Body.String())
	}
	return result.Organization.ID, created.Body.Bytes()
}

func TestSelfServeOrganizationHTTPFlow(t *testing.T) {
	store := newFakeOrganizationStore()
	client, _, ownerID, cookies, csrf := selfServeClient(t, store)
	ctx := context.Background()

	orgID, createdBody := createSelfServeOrganization(t, client, cookies, csrf)
	// Pin the exact wire key the README's jq expression uses. Go's decoder
	// accepts "id" case-insensitively, so a struct-only assertion would miss
	// a casing change that breaks the documented curl flow.
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(createdBody, &wire); err != nil {
		t.Fatalf("decode wire = %v", err)
	}
	var orgWire map[string]json.RawMessage
	if err := json.Unmarshal(wire["Organization"], &orgWire); err != nil {
		t.Fatalf("decode wire Organization = %v", err)
	}
	if _, ok := orgWire["ID"]; !ok {
		t.Fatalf("create response has no Organization.ID key: %s", createdBody)
	}
	if _, ok := orgWire["id"]; ok {
		t.Fatalf("create response has lowercase Organization.id key: %s", createdBody)
	}
	role, err := store.MemberRole(ctx, orgID, ownerID)
	if err != nil || role != "owner" {
		t.Fatalf("creator role = %q, %v; want owner, nil", role, err)
	}

	listed := getSelfServe(t, client, "/organizations", cookies)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), orgID) {
		t.Fatalf("list status = %d, body = %s", listed.Code, listed.Body.String())
	}

	for _, tc := range []struct{ path, body string }{
		{"/organization-members/add", fmt.Sprintf(`{"organization_id":%q,"user_id":"member-1","role":"member"}`, orgID)},
		{"/organization-members/role", fmt.Sprintf(`{"organization_id":%q,"user_id":"member-1","role":"admin"}`, orgID)},
		{"/organization-members/remove", fmt.Sprintf(`{"organization_id":%q,"user_id":"member-1"}`, orgID)},
	} {
		rec := postSelfServe(t, client, tc.path, tc.body, cookies, csrf)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, body = %s", tc.path, rec.Code, rec.Body.String())
		}
	}
}

func TestSelfServeOrganizationDeniesMemberMutations(t *testing.T) {
	store := newFakeOrganizationStore()
	client, _, _, ownerCookies, ownerCSRF := selfServeClient(t, store)
	ctx := context.Background()

	created := postSelfServe(t, client, "/organizations", `{"name":"Acme"}`, ownerCookies, ownerCSRF)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", created.Code, created.Body.String())
	}
	var result struct {
		Organization struct {
			ID string `json:"id"`
		} `json:"Organization"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || result.Organization.ID == "" {
		t.Fatalf("decode create = %v, body = %s", err, created.Body.String())
	}
	orgID := result.Organization.ID

	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "member@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp member: %v", err)
	}
	member, err := client.SignIn(ctx, signet.SignInInput{Email: "member@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn member: %v", err)
	}
	add := postSelfServe(t, client, "/organization-members/add",
		fmt.Sprintf(`{"organization_id":%q,"user_id":%q,"role":"member"}`, orgID, member.User.ID), ownerCookies, ownerCSRF)
	if add.Code != http.StatusOK {
		t.Fatalf("owner add status = %d, body = %s", add.Code, add.Body.String())
	}

	memberCookies, memberCSRF := signInSelfServe(t, client, "member@example.com")
	denied := postSelfServe(t, client, "/organization-members/add",
		fmt.Sprintf(`{"organization_id":%q,"user_id":"outsider","role":"member"}`, orgID), memberCookies, memberCSRF)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("member add status = %d, want 403; body = %s", denied.Code, denied.Body.String())
	}
	listed := getSelfServe(t, client, "/organization-members?organization_id="+orgID, memberCookies)
	if listed.Code != http.StatusForbidden {
		t.Fatalf("member list status = %d, want 403; body = %s", listed.Code, listed.Body.String())
	}
}

func TestSelfServeOrganizationDeniesNonMembers(t *testing.T) {
	store := newFakeOrganizationStore()
	client, _, _, ownerCookies, ownerCSRF := selfServeClient(t, store)

	created := postSelfServe(t, client, "/organizations", `{"name":"Acme"}`, ownerCookies, ownerCSRF)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", created.Code, created.Body.String())
	}
	var result struct {
		Organization struct {
			ID string `json:"id"`
		} `json:"Organization"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || result.Organization.ID == "" {
		t.Fatalf("decode create = %v, body = %s", err, created.Body.String())
	}
	orgID := result.Organization.ID

	if _, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "outsider@example.com", Password: "correct horse",
	}); err != nil {
		t.Fatalf("SignUp outsider: %v", err)
	}
	outsiderCookies, outsiderCSRF := signInSelfServe(t, client, "outsider@example.com")

	listed := getSelfServe(t, client, "/organization-members?organization_id="+orgID, outsiderCookies)
	if listed.Code != http.StatusForbidden {
		t.Fatalf("non-member list status = %d, want 403; body = %s", listed.Code, listed.Body.String())
	}
	added := postSelfServe(t, client, "/organization-members/add",
		fmt.Sprintf(`{"organization_id":%q,"user_id":"x","role":"member"}`, orgID), outsiderCookies, outsiderCSRF)
	if added.Code != http.StatusForbidden {
		t.Fatalf("non-member add status = %d, want 403; body = %s", added.Code, added.Body.String())
	}
	admin := getSelfServe(t, client, "/admin-users", outsiderCookies)
	if admin.Code != http.StatusForbidden {
		t.Fatalf("admin-users status = %d, want 403; body = %s", admin.Code, admin.Body.String())
	}
}

func TestSelfServeOrganizationRequiresFreshSession(t *testing.T) {
	client, _, _, _, _ := selfServeClient(t, newFakeOrganizationStore())

	csrfRec := httptest.NewRecorder()
	client.Handler().ServeHTTP(csrfRec, httptest.NewRequest(http.MethodGet, "/auth/csrf-token", nil))
	if csrfRec.Code != http.StatusOK {
		t.Fatalf("csrf-token status = %d", csrfRec.Code)
	}
	var csrfBody struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(csrfRec.Body.Bytes(), &csrfBody); err != nil || csrfBody.Token == "" {
		t.Fatalf("csrf-token body = %s, err = %v", csrfRec.Body.String(), err)
	}
	csrfCookies := csrfRec.Result().Cookies()

	anonymous := postSelfServe(t, client, "/organizations", `{"name":"Acme"}`, csrfCookies, csrfBody.Token)
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous create status = %d, want 401; body = %s", anonymous.Code, anonymous.Body.String())
	}
	stale := append([]*http.Cookie{}, csrfCookies...)
	stale = append(stale, &http.Cookie{
		Name: "__Host-signet_session", Value: "stale-token", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	rec := postSelfServe(t, client, "/organizations", `{"name":"Acme"}`, stale, csrfBody.Token)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale create status = %d, want 401; body = %s", rec.Code, rec.Body.String())
	}
}

// A session can still authenticate while being outside Accounts.FreshWindow.
// Guarded organization mutations must reject it with 403, not serve the call.
func TestSelfServeOrganizationRequiresFreshSessionWindow(t *testing.T) {
	authStore := testutil.NewStore()
	client, _, _, cookies, csrf := selfServeClientWithStore(t, newFakeOrganizationStore(), authStore)

	created := postSelfServe(t, client, "/organizations", `{"name":"Acme"}`, cookies, csrf)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", created.Code, created.Body.String())
	}
	var result struct {
		Organization struct {
			ID string
		} `json:"Organization"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || result.Organization.ID == "" {
		t.Fatalf("decode create = %v, body = %s", err, created.Body.String())
	}
	orgID := result.Organization.ID

	// Keep the session resolvable but older than the 5-minute freshness window.
	for _, session := range authStore.Sessions {
		session.CreatedAt = time.Now().Add(-time.Hour)
	}
	staleCreate := postSelfServe(t, client, "/organizations", `{"name":"Stale"}`, cookies, csrf)
	if staleCreate.Code != http.StatusForbidden {
		t.Fatalf("stale-window create status = %d, want 403; body = %s", staleCreate.Code, staleCreate.Body.String())
	}
	staleAdd := postSelfServe(t, client, "/organization-members/add",
		fmt.Sprintf(`{"organization_id":%q,"user_id":"member-1","role":"member"}`, orgID), cookies, csrf)
	if staleAdd.Code != http.StatusForbidden {
		t.Fatalf("stale-window add status = %d, want 403; body = %s", staleAdd.Code, staleAdd.Body.String())
	}
}
