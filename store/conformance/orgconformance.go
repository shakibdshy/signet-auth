package conformance

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/shakibdshy/signet-auth"
)

// RunOrganizations executes the OrganizationStore conformance suite. The
// factory must return a fresh OrganizationStore for each case. It pins the
// semantics the organization features depend on: List is scoped to the
// memberships of the User it is given, MemberRole misses answer ErrNotFound,
// and removing a missing Membership is not an error.
func RunOrganizations(t *testing.T, factory func(t *testing.T) signet.OrganizationStore) {
	t.Helper()
	cases := []struct {
		name string
		fn   func(*testing.T, signet.OrganizationStore)
	}{
		{"organizations", testOrganizations},
		{"members", testMembers},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, factory(t)) })
	}
}

// RunAdminUsers executes the AdminUserStore conformance suite. The factory
// must return a fresh AdminUserStore for each case together with a seed
// function that persists one User in the same storage.
func RunAdminUsers(t *testing.T, factory func(t *testing.T) (signet.AdminUserStore, func(context.Context, *signet.User) error)) {
	t.Helper()
	cases := []struct {
		name string
		fn   func(*testing.T, signet.AdminUserStore, func(context.Context, *signet.User) error)
	}{
		{"admin_users", testAdminUsers},
	}
	for _, tc := range cases {
		store, seed := factory(t)
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, store, seed) })
	}
}

func testOrganizations(t *testing.T, store signet.OrganizationStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	org := &signet.Organization{ID: "org-1", OwnerID: "user-1", Name: "Acme", CreatedAt: now}
	if err := store.Create(ctx, org); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// List is scoped to the User's Memberships. The store may seed the
	// owner's Membership at Create time, so assert only the strong part of
	// the contract here: an unknown User sees no Organizations of their own.
	theirs, err := store.List(ctx, "user-no-memberships")
	if err != nil {
		t.Fatalf("List(unknown user): %v", err)
	}
	if len(theirs) != 0 {
		t.Fatalf("List(user with no memberships) = %d organizations, want 0", len(theirs))
	}
}

func testMembers(t *testing.T, store signet.OrganizationStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	org := &signet.Organization{ID: "org-1", OwnerID: "user-1", Name: "Acme", CreatedAt: now}
	if err := store.Create(ctx, org); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := store.MemberRole(ctx, org.ID, "user-miss"); !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("MemberRole(missing membership) error = %v, want ErrNotFound", err)
	}
	if err := store.AddMember(ctx, org.ID, "user-a", "member"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	role, err := store.MemberRole(ctx, org.ID, "user-a")
	if err != nil || role != "member" {
		t.Fatalf("MemberRole after AddMember = (%q, %v)", role, err)
	}
	if err := store.SetMemberRole(ctx, org.ID, "user-a", "admin"); err != nil {
		t.Fatalf("SetMemberRole: %v", err)
	}
	role, err = store.MemberRole(ctx, org.ID, "user-a")
	if err != nil || role != "admin" {
		t.Fatalf("MemberRole after SetMemberRole = (%q, %v)", role, err)
	}

	members, err := store.Members(ctx, org.ID)
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	index := slices.IndexFunc(members, func(m *signet.MemberInfo) bool { return m.UserID == "user-a" })
	if index < 0 || members[index].Role != "admin" {
		t.Fatalf("Members = %+v, want user-a as admin", members)
	}

	if err := store.RemoveMember(ctx, org.ID, "user-a"); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if _, err := store.MemberRole(ctx, org.ID, "user-a"); !errors.Is(err, signet.ErrNotFound) {
		t.Fatalf("MemberRole after RemoveMember error = %v, want ErrNotFound", err)
	}
	// Removing an already-removed Membership must not fail: the library
	// treats removal as idempotent.
	if err := store.RemoveMember(ctx, org.ID, "user-a"); err != nil {
		t.Fatalf("RemoveMember of missing membership: %v", err)
	}
}

func testAdminUsers(t *testing.T, store signet.AdminUserStore, seed func(context.Context, *signet.User) error) {
	t.Helper()
	ctx := context.Background()

	empty, err := store.ListUsersForAdmin(ctx)
	if err != nil || len(empty) != 0 {
		t.Fatalf("ListUsersForAdmin on an empty store = (%d users, %v)", len(empty), err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	want := []*signet.User{
		{ID: "user-1", Email: "ada@example.com", Name: "Ada", CreatedAt: now, UpdatedAt: now},
		{ID: "user-2", Email: "grace@example.com", Name: "Grace", CreatedAt: now, UpdatedAt: now},
	}
	for _, user := range want {
		if err := seed(ctx, user); err != nil {
			t.Fatalf("seed %s: %v", user.ID, err)
		}
	}
	got, err := store.ListUsersForAdmin(ctx)
	if err != nil {
		t.Fatalf("ListUsersForAdmin: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("ListUsersForAdmin = %d users, want %d", len(got), len(want))
	}
	for _, user := range want {
		index := slices.IndexFunc(got, func(u *signet.User) bool { return u.ID == user.ID })
		if index < 0 || got[index].Email != user.Email || got[index].Name != user.Name {
			t.Fatalf("ListUsersForAdmin is missing %s or lost its fields: %+v", user.ID, got)
		}
	}
}
