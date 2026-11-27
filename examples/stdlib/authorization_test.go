package main

import (
	"context"
	"testing"

	"github.com/shakibdshy/signet-auth"
)

// exampleOrgStore is a test-only in-memory OrganizationStore with the same
// membership semantics as the Postgres store used by the running example.
type exampleOrgStore struct {
	members map[string]map[string]string // orgID -> userID -> role
}

var _ signet.OrganizationStore = (*exampleOrgStore)(nil)

func (s *exampleOrgStore) Create(_ context.Context, org *signet.Organization) error {
	s.members[org.ID] = map[string]string{org.OwnerID: "owner"}
	return nil
}

func (s *exampleOrgStore) List(context.Context, string) ([]*signet.Organization, error) {
	return nil, nil
}

func (s *exampleOrgStore) AddMember(_ context.Context, orgID, userID, role string) error {
	if s.members[orgID] == nil {
		s.members[orgID] = make(map[string]string)
	}
	s.members[orgID][userID] = role
	return nil
}

func (s *exampleOrgStore) RemoveMember(_ context.Context, orgID, userID string) error {
	delete(s.members[orgID], userID)
	return nil
}

func (s *exampleOrgStore) MemberRole(_ context.Context, orgID, userID string) (string, error) {
	role, ok := s.members[orgID][userID]
	if !ok {
		return "", signet.ErrNotFound
	}
	return role, nil
}

func (s *exampleOrgStore) SetMemberRole(_ context.Context, orgID, userID, role string) error {
	s.members[orgID][userID] = role
	return nil
}

func (s *exampleOrgStore) Members(context.Context, string) ([]*signet.MemberInfo, error) {
	return nil, nil
}

func TestNewAuthorizerGrantsOnlyOrgCreate(t *testing.T) {
	a := newAuthorizer()
	if !a.Authorize(context.Background(), "u1", "organizations", "create") {
		t.Fatal("user role must grant organizations:create")
	}
	for _, p := range []struct{ resource, action string }{
		{"users", "ban"}, {"users", "set-role"}, {"sessions", "revoke"},
		{"api-keys", "create"}, {"api-keys", "revoke"},
	} {
		if a.Authorize(context.Background(), "u1", p.resource, p.action) {
			t.Fatalf("user role must not grant %s:%s", p.resource, p.action)
		}
	}
	if roles := a.Roles(context.Background(), "u1"); len(roles) != 1 || roles[0] != "user" {
		t.Fatalf("roles = %v; want [user]", roles)
	}
}

func TestNewAuthorizeInOwnerAdminOnly(t *testing.T) {
	store := &exampleOrgStore{members: map[string]map[string]string{
		"org1": {"owner1": "owner", "admin1": "admin", "member1": "member"},
	}}
	in := newAuthorizeIn(store)
	for _, user := range []string{"owner1", "admin1"} {
		for _, action := range []string{"member-add", "member-remove", "member-role"} {
			if !in.AuthorizeIn(context.Background(), user, "org1", "organizations", action) {
				t.Fatalf("%s denied organizations:%s", user, action)
			}
		}
	}
	for _, user := range []string{"member1", "outsider"} {
		if in.AuthorizeIn(context.Background(), user, "org1", "organizations", "member-add") {
			t.Fatalf("%s must be denied", user)
		}
	}
	if in.AuthorizeIn(context.Background(), "owner1", "org1", "organizations", "create") {
		t.Fatal("org-scoped policy must not grant global organizations:create")
	}
}
