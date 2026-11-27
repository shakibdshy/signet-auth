package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/shakibdshy/signet-auth"
)

func createOrgForEmailTest(t *testing.T, client *signet.Client, cookies []*http.Cookie, csrf string) string {
	t.Helper()
	orgID, _ := createSelfServeOrganization(t, client, cookies, csrf)
	return orgID
}

func signUpEmailTestUser(t *testing.T, client *signet.Client, email string) string {
	t.Helper()
	signUp, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: email, Password: "correct horse", Name: email,
	})
	if err != nil {
		t.Fatalf("SignUp %s: %v", email, err)
	}
	return signUp.User.ID
}

func assertMembershipRole(t *testing.T, store *fakeOrganizationStore, orgID, userID, want string) {
	t.Helper()
	role, err := store.MemberRole(context.Background(), orgID, userID)
	if err != nil || role != want {
		t.Fatalf("membership role = %q, %v; want %s, nil", role, err, want)
	}
}

func TestAddOrganizationMemberByEmailRequiresOwnerOrAdmin(t *testing.T) {
	store := newFakeOrganizationStore()
	client, _, _, ownerCookies, ownerCSRF := selfServeClient(t, store)
	orgID := createOrgForEmailTest(t, client, ownerCookies, ownerCSRF)

	for _, email := range []string{"member@example.com", "outsider@example.com"} {
		signUpEmailTestUser(t, client, email)
	}
	added := postSelfServe(t, client, "/organization-members/add",
		fmt.Sprintf(`{"organization_id":%q,"email":"member@example.com","role":"member"}`, orgID), ownerCookies, ownerCSRF)
	if added.Code != http.StatusOK {
		t.Fatalf("owner add status = %d, body = %s", added.Code, added.Body.String())
	}

	memberCookies, memberCSRF := signInSelfServe(t, client, "member@example.com")
	memberAdd := postSelfServe(t, client, "/organization-members/add",
		fmt.Sprintf(`{"organization_id":%q,"email":"outsider@example.com","role":"admin"}`, orgID), memberCookies, memberCSRF)
	if memberAdd.Code != http.StatusForbidden {
		t.Fatalf("plain Member add status = %d, want 403; body = %s", memberAdd.Code, memberAdd.Body.String())
	}

	outsiderCookies, outsiderCSRF := signInSelfServe(t, client, "outsider@example.com")
	outsiderAdd := postSelfServe(t, client, "/organization-members/add",
		fmt.Sprintf(`{"organization_id":%q,"email":"member@example.com","role":"admin"}`, orgID), outsiderCookies, outsiderCSRF)
	if outsiderAdd.Code != http.StatusForbidden {
		t.Fatalf("non-member add status = %d, want 403; body = %s", outsiderAdd.Code, outsiderAdd.Body.String())
	}
}

func TestAddOrganizationMemberRequiresExactlyOneIdentifier(t *testing.T) {
	store := newFakeOrganizationStore()
	client, _, _, cookies, csrf := selfServeClient(t, store)
	orgID := createOrgForEmailTest(t, client, cookies, csrf)

	for name, body := range map[string]string{
		"both":    fmt.Sprintf(`{"organization_id":%q,"user_id":"member-1","email":"member@example.com","role":"member"}`, orgID),
		"neither": fmt.Sprintf(`{"organization_id":%q,"role":"member"}`, orgID),
	} {
		rec := postSelfServe(t, client, "/organization-members/add", body, cookies, csrf)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_input") {
			t.Fatalf("%s identifiers status = %d, body = %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestAddOrganizationMemberByBlankEmailIsInvalidInput(t *testing.T) {
	store := newFakeOrganizationStore()
	client, _, _, cookies, csrf := selfServeClient(t, store)
	orgID := createOrgForEmailTest(t, client, cookies, csrf)

	rec := postSelfServe(t, client, "/organization-members/add",
		fmt.Sprintf(`{"organization_id":%q,"email":"   ","role":"member"}`, orgID), cookies, csrf)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_input") {
		t.Fatalf("blank email status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAddOrganizationMemberByUnknownEmail(t *testing.T) {
	store := newFakeOrganizationStore()
	client, _, _, cookies, csrf := selfServeClient(t, store)
	orgID := createOrgForEmailTest(t, client, cookies, csrf)

	rec := postSelfServe(t, client, "/organization-members/add",
		fmt.Sprintf(`{"organization_id":%q,"email":"nobody@example.com","role":"member"}`, orgID), cookies, csrf)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "user_not_found") {
		t.Fatalf("unknown email status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAddOrganizationMemberByEmailNormalizesAddress(t *testing.T) {
	store := newFakeOrganizationStore()
	client, _, _, cookies, csrf := selfServeClient(t, store)
	orgID := createOrgForEmailTest(t, client, cookies, csrf)
	memberID := signUpEmailTestUser(t, client, "member@example.com")

	rec := postSelfServe(t, client, "/organization-members/add",
		fmt.Sprintf(`{"organization_id":%q,"email":"  MEMBER@Example.COM  ","role":"member"}`, orgID), cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("normalized email status = %d, body = %s", rec.Code, rec.Body.String())
	}
	assertMembershipRole(t, store, orgID, memberID, "member")
}

func TestAddOrganizationMemberByEmail(t *testing.T) {
	store := newFakeOrganizationStore()
	client, _, _, cookies, csrf := selfServeClient(t, store)
	orgID := createOrgForEmailTest(t, client, cookies, csrf)
	memberID := signUpEmailTestUser(t, client, "member@example.com")

	rec := postSelfServe(t, client, "/organization-members/add",
		fmt.Sprintf(`{"organization_id":%q,"email":"member@example.com","role":"member"}`, orgID), cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("add by email status = %d, body = %s", rec.Code, rec.Body.String())
	}
	assertMembershipRole(t, store, orgID, memberID, "member")
}
