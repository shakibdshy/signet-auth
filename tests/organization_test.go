package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

type fakeOrganizationStore struct {
	orgs    map[string]*signet.Organization
	members map[string]map[string]string // orgID -> userID -> role
}

func newFakeOrganizationStore() *fakeOrganizationStore {
	return &fakeOrganizationStore{
		orgs:    make(map[string]*signet.Organization),
		members: make(map[string]map[string]string),
	}
}

func (s *fakeOrganizationStore) Create(_ context.Context, org *signet.Organization) error {
	s.orgs[org.ID] = org
	s.members[org.ID] = map[string]string{org.OwnerID: "owner"}
	return nil
}

// List is membership-scoped, matching the OrganizationStore contract the
// conformance suite pins: a User's Organizations are the ones they belong to.
func (s *fakeOrganizationStore) List(_ context.Context, userID string) ([]*signet.Organization, error) {
	out := make([]*signet.Organization, 0)
	ids := make([]string, 0, len(s.members))
	for orgID, roles := range s.members {
		if _, ok := roles[userID]; ok {
			ids = append(ids, orgID)
		}
	}
	slices.Sort(ids)
	for _, orgID := range ids {
		if org, ok := s.orgs[orgID]; ok {
			out = append(out, org)
		}
	}
	return out, nil
}

func (s *fakeOrganizationStore) AddMember(_ context.Context, orgID, userID, role string) error {
	if s.members[orgID] == nil {
		s.members[orgID] = make(map[string]string)
	}
	s.members[orgID][userID] = role
	return nil
}

func (s *fakeOrganizationStore) RemoveMember(_ context.Context, orgID, userID string) error {
	delete(s.members[orgID], userID)
	return nil
}

func (s *fakeOrganizationStore) Members(_ context.Context, orgID string) ([]*signet.MemberInfo, error) {
	out := make([]*signet.MemberInfo, 0)
	for userID, role := range s.members[orgID] {
		out = append(out, &signet.MemberInfo{UserID: userID, Role: role})
	}
	return out, nil
}

func (s *fakeOrganizationStore) MemberRole(_ context.Context, orgID, userID string) (string, error) {
	role, ok := s.members[orgID][userID]
	if !ok {
		return "", signet.ErrNotFound
	}
	return role, nil
}

func (s *fakeOrganizationStore) SetMemberRole(_ context.Context, orgID, userID, role string) error {
	s.members[orgID][userID] = role
	return nil
}

func organizationClient(t *testing.T, store *fakeOrganizationStore, authorizer signet.Authorizer, sink signet.AuditSink) *signet.Client {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.OrganizationStore = store
	cfg.Authorizer = authorizer
	cfg.AuditSink = sink
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestOrganizationCreateMemberAndActive(t *testing.T) {
	store := newFakeOrganizationStore()
	authorizer := &fakeAuthorizer{allowed: map[string]bool{
		"organizations:create": true, "organizations:member-add": true,
	}}
	authStore := testutil.NewStore()
	cfg := testutil.NewConfig()
	cfg.Store = authStore
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.OrganizationStore = store
	cfg.Authorizer = authorizer
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "owner@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	ownerID := signUp.User.ID
	signIn, err := client.SignIn(ctx, signet.SignInInput{Email: "owner@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	token := signIn.SessionToken
	created, err := client.CreateOrganization(ctx, signet.CreateOrganizationInput{
		OwnerID: ownerID, Name: "Acme", SessionToken: token,
	})
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := client.AddOrganizationMember(ctx, signet.AddOrganizationMemberInput{
		OrgID: created.Organization.ID, UserID: "user-1", Role: "member", ActorID: ownerID, SessionToken: token,
	}); err != nil {
		t.Fatalf("AddOrganizationMember: %v", err)
	}
	members, err := client.ListOrganizationMembers(ctx, created.Organization.ID, ownerID, token)
	if err != nil || len(members.Members) != 2 {
		t.Fatalf("members = %+v, err = %v", members, err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/set-active-organization",
		strings.NewReader(`{"org_id":"`+created.Organization.ID+`"}`))
	req.AddCookie(&http.Cookie{Name: "__Host-signet_session", Value: token, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", csrfToken)
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("set active status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestOrganizationSetActiveRejectsNonMember(t *testing.T) {
	store := newFakeOrganizationStore()
	authorizer := &fakeAuthorizer{allowed: map[string]bool{"organizations:create": true}}
	client := organizationClient(t, store, authorizer, nil)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "owner@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn, err := client.SignIn(ctx, signet.SignInInput{Email: "owner@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	created, err := client.CreateOrganization(ctx, signet.CreateOrganizationInput{
		OwnerID: "owner-1", Name: "Acme", SessionToken: signIn.SessionToken,
	})
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	err = client.SetActiveOrganization(ctx, signet.SetActiveOrganizationInput{
		OrgID: created.Organization.ID, UserID: "outsider-1", SessionToken: signIn.SessionToken,
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("non-member error = %v", err)
	}
}

func TestOrganizationTamperedCookieIgnored(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.OrganizationStore = newFakeOrganizationStore()
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/active-organization", nil)
	req.AddCookie(&http.Cookie{Name: "signet_active_org", Value: "tampered.value", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rr := httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"ID":""`) {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

type recordingAuthorizeIn struct{ calls int }

func (a *recordingAuthorizeIn) AuthorizeIn(context.Context, string, string, string, string) bool {
	a.calls++
	return true
}

type orgAuditSink struct{ events []signet.AuditEvent }

func (s *orgAuditSink) Record(_ context.Context, event signet.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func orgClientWithExtras(t *testing.T, store *fakeOrganizationStore, authorizer signet.Authorizer, orgIn signet.AuthorizeIn, sink signet.AuditSink) (*signet.Client, string) {
	t.Helper()
	cfg := testutil.NewConfig()
	authStore := testutil.NewStore()
	cfg.Store = authStore
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.OrganizationStore = store
	cfg.Authorizer = authorizer
	cfg.AuthorizeIn = orgIn
	cfg.AuditSink = sink
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "owner@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn, err := client.SignIn(ctx, signet.SignInInput{Email: "owner@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	return client, signIn.SessionToken
}

func TestOrganizationUsesAuthorizeIn(t *testing.T) {
	store := newFakeOrganizationStore()
	orgIn := &recordingAuthorizeIn{}
	client, token := orgClientWithExtras(t, store, &fakeAuthorizer{
		allowed: map[string]bool{"organizations:create": true},
	}, orgIn, nil)
	ctx := context.Background()
	created, err := client.CreateOrganization(ctx, signet.CreateOrganizationInput{
		OwnerID: "owner-1", Name: "Acme", SessionToken: token,
	})
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := client.AddOrganizationMember(ctx, signet.AddOrganizationMemberInput{
		OrgID: created.Organization.ID, UserID: "user-1", Role: "member", ActorID: "owner-1", SessionToken: token,
	}); err != nil {
		t.Fatalf("AddOrganizationMember: %v", err)
	}
	if orgIn.calls == 0 {
		t.Fatal("AuthorizeIn was never called for the org-scoped operation")
	}
}

func TestOrganizationMutationsRequireFreshSession(t *testing.T) {
	store := newFakeOrganizationStore()
	client, _ := orgClientWithExtras(t, store, &fakeAuthorizer{
		allowed: map[string]bool{"organizations:create": true},
	}, nil, nil)
	_, err := client.CreateOrganization(context.Background(), signet.CreateOrganizationInput{
		OwnerID: "owner-1", Name: "Acme", SessionToken: "stale-token",
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("stale create error = %v", err)
	}
}

func TestOrganizationAuditSuccessAndDenial(t *testing.T) {
	store := newFakeOrganizationStore()
	sink := &orgAuditSink{}
	client, token := orgClientWithExtras(t, store, &fakeAuthorizer{
		allowed: map[string]bool{"organizations:create": true},
	}, nil, sink)
	ctx := context.Background()
	if _, err := client.CreateOrganization(ctx, signet.CreateOrganizationInput{
		OwnerID: "owner-1", Name: "Acme", SessionToken: token,
	}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if _, err := client.CreateOrganization(ctx, signet.CreateOrganizationInput{
		OwnerID: "owner-1", Name: "Other", SessionToken: "stale-token",
	}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("stale create error = %v", err)
	}
	names := make(map[string]int)
	for _, event := range sink.events {
		names[event.Name+"|"+event.Outcome]++
	}
	if names["organization_created|success"] == 0 || names["authorization_denied|denied"] == 0 {
		t.Fatalf("audit events = %+v", sink.events)
	}
}

func TestOrganizationHTTPEndpoints(t *testing.T) {
	store := newFakeOrganizationStore()
	authorizer := &fakeAuthorizer{allowed: map[string]bool{
		"organizations:create": true, "organizations:member-add": true,
		"organizations:member-remove": true, "organizations:member-role": true,
	}}
	client, token := orgClientWithExtras(t, store, authorizer, nil, nil)
	cookies := &http.Cookie{Name: "__Host-signet_session", Value: token, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	post := func(path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.AddCookie(cookies)
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfToken)
		client.Handler().ServeHTTP(rr, req)
		return rr
	}
	created := post("/organizations", `{"name":"Acme"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", created.Code, created.Body.String())
	}
	var result struct {
		Organization struct {
			ID string `json:"id"`
		} `json:"Organization"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || result.Organization.ID == "" {
		t.Fatalf("decode = %v body = %s", err, created.Body.String())
	}
	orgID := result.Organization.ID
	for _, path := range []string{
		"/organization-members/add", "/organization-members/role", "/organization-members/remove",
	} {
		rr := post(path, `{"organization_id":"`+orgID+`","user_id":"member-1","role":"admin"}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status = %d body = %s", path, rr.Code, rr.Body.String())
		}
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/organization-members?organization_id="+orgID, nil)
	req.AddCookie(cookies)
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Members") {
		t.Fatalf("members status = %d body = %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/organizations", nil)
	req.AddCookie(cookies)
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), orgID) {
		t.Fatalf("list status = %d body = %s", rr.Code, rr.Body.String())
	}
	if rr := post("/clear-active-organization", `{}`); rr.Code != http.StatusOK {
		t.Fatalf("clear status = %d", rr.Code)
	}
}
