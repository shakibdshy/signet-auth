package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
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

func (s *fakeOrganizationStore) List(context.Context, string) ([]*signet.Organization, error) {
	out := make([]*signet.Organization, 0, len(s.orgs))
	for _, org := range s.orgs {
		out = append(out, org)
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
	created, err := client.CreateOrganization(ctx, signet.CreateOrganizationInput{OwnerID: ownerID, Name: "Acme"})
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := client.AddOrganizationMember(ctx, signet.AddOrganizationMemberInput{
		OrgID: created.Organization.ID, UserID: "user-1", Role: "member", ActorID: ownerID,
	}); err != nil {
		t.Fatalf("AddOrganizationMember: %v", err)
	}
	members, err := client.ListOrganizationMembers(ctx, signet.ListOrganizationMembersInput{
		OrgID: created.Organization.ID, UserID: ownerID,
	})
	if err != nil || len(members.Members) != 2 {
		t.Fatalf("members = %+v, err = %v", members, err)
	}
	result, err := client.SignIn(ctx, signet.SignInInput{Email: "owner@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/set-active-organization",
		strings.NewReader(`{"org_id":"`+created.Organization.ID+`"}`))
	req.AddCookie(&http.Cookie{Name: "__Host-signet_session", Value: result.SessionToken, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
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
	created, err := client.CreateOrganization(ctx, signet.CreateOrganizationInput{OwnerID: "owner-1", Name: "Acme"})
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	err = client.SetActiveOrganization(ctx, signet.SetActiveOrganizationInput{
		OrgID: created.Organization.ID, UserID: "outsider-1",
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
