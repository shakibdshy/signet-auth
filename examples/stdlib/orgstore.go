package main

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shakibdshy/signet-auth"
)

var _ signet.OrganizationStore = (*orgStore)(nil)

const createOrganizationsTable = `
CREATE TABLE IF NOT EXISTS signet_organizations (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL
)`

const createOrganizationMembersTable = `
CREATE TABLE IF NOT EXISTS signet_organization_members (
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id) REFERENCES signet_organizations(id) ON DELETE CASCADE
)`

const createOrgMembersUserIndex = `
CREATE INDEX IF NOT EXISTS idx_signet_org_members_user ON signet_organization_members(user_id)`

const insertOrganization = `
INSERT INTO signet_organizations (id, owner_id, name, created_at) VALUES ($1, $2, $3, $4)`

const upsertOrganizationMember = `
INSERT INTO signet_organization_members (org_id, user_id, role) VALUES ($1, $2, $3)
ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role`

const selectOrganizationsForUser = `
SELECT o.id, o.owner_id, o.name, o.created_at
FROM signet_organizations o
JOIN signet_organization_members m ON m.org_id = o.id
WHERE m.user_id = $1
ORDER BY o.created_at, o.id`

const selectOrganizationMemberRole = `
SELECT role FROM signet_organization_members WHERE org_id = $1 AND user_id = $2`

const selectOrganizationMembers = `
SELECT user_id, role FROM signet_organization_members WHERE org_id = $1 ORDER BY user_id`

const deleteOrganizationMember = `
DELETE FROM signet_organization_members WHERE org_id = $1 AND user_id = $2`

// orgStore is the example application's Postgres-backed OrganizationStore. It
// persists organization state owned by the application, not by Signet.
type orgStore struct {
	pool *pgxpool.Pool
}

func newOrgStore(pool *pgxpool.Pool) *orgStore {
	return &orgStore{pool: pool}
}

// Migrate creates the example's organization tables. Every statement is
// idempotent, so repeated calls are safe.
func (s *orgStore) Migrate(ctx context.Context) error {
	for _, statement := range []string{
		createOrganizationsTable,
		createOrganizationMembersTable,
		createOrgMembersUserIndex,
	} {
		if _, err := s.pool.Exec(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

// Create persists an Organization and its creator as its owner atomically.
func (s *orgStore) Create(ctx context.Context, org *signet.Organization) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, insertOrganization, org.ID, org.OwnerID, org.Name, org.CreatedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, upsertOrganizationMember, org.ID, org.OwnerID, "owner"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// List returns every Organization the User is a member of.
func (s *orgStore) List(ctx context.Context, userID string) ([]*signet.Organization, error) {
	rows, err := s.pool.Query(ctx, selectOrganizationsForUser, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orgs []*signet.Organization
	for rows.Next() {
		org := &signet.Organization{}
		if err := rows.Scan(&org.ID, &org.OwnerID, &org.Name, &org.CreatedAt); err != nil {
			return nil, err
		}
		orgs = append(orgs, org)
	}
	return orgs, rows.Err()
}

// AddMember adds or updates a User's role in an Organization.
func (s *orgStore) AddMember(ctx context.Context, orgID, userID, role string) error {
	_, err := s.pool.Exec(ctx, upsertOrganizationMember, orgID, userID, role)
	return err
}

// RemoveMember removes a User from an Organization.
func (s *orgStore) RemoveMember(ctx context.Context, orgID, userID string) error {
	_, err := s.pool.Exec(ctx, deleteOrganizationMember, orgID, userID)
	return err
}

// MemberRole returns a User's role in an Organization or ErrNotFound.
func (s *orgStore) MemberRole(ctx context.Context, orgID, userID string) (string, error) {
	var role string
	err := s.pool.QueryRow(ctx, selectOrganizationMemberRole, orgID, userID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", signet.ErrNotFound
	}
	return role, err
}

// SetMemberRole changes a User's role in an Organization.
func (s *orgStore) SetMemberRole(ctx context.Context, orgID, userID, role string) error {
	_, err := s.pool.Exec(ctx, upsertOrganizationMember, orgID, userID, role)
	return err
}

// Members lists an Organization's Memberships.
func (s *orgStore) Members(ctx context.Context, orgID string) ([]*signet.MemberInfo, error) {
	rows, err := s.pool.Query(ctx, selectOrganizationMembers, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []*signet.MemberInfo
	for rows.Next() {
		member := &signet.MemberInfo{}
		if err := rows.Scan(&member.UserID, &member.Role); err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, rows.Err()
}
