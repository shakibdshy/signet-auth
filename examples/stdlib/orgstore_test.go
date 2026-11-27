package main

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shakibdshy/signet-auth"
)

var _ signet.OrganizationStore = (*orgStore)(nil)

func TestOrgStoreCreatePersistsOwner(t *testing.T) {
	dsn := os.Getenv("SIGNET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set SIGNET_TEST_DATABASE_URL to exercise the Postgres org store")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := newOrgStore(pool)
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, "DELETE FROM signet_organization_members; DELETE FROM signet_organizations")
	if err != nil {
		t.Fatal(err)
	}
	org := &signet.Organization{ID: "org-1", OwnerID: "user-1", Name: "Acme"}
	if err := store.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	role, err := store.MemberRole(ctx, "org-1", "user-1")
	if err != nil || role != "owner" {
		t.Fatalf("creator role = %q, %v; want owner, nil", role, err)
	}
	if _, err := store.MemberRole(ctx, "org-1", "outsider"); err != signet.ErrNotFound {
		t.Fatalf("non-member error = %v; want ErrNotFound", err)
	}
	listed, err := store.List(ctx, "user-1")
	if err != nil || len(listed) != 1 || listed[0].ID != "org-1" {
		t.Fatalf("list = %+v, %v", listed, err)
	}
	members, err := store.Members(ctx, "org-1")
	if err != nil || len(members) != 1 || members[0].UserID != "user-1" || members[0].Role != "owner" {
		t.Fatalf("members = %+v, %v", members, err)
	}
}
