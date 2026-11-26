package sqlite_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/shakibdshy/signet-auth/internal/sqlfiles"
	"github.com/shakibdshy/signet-auth/store/sqlite"
)

// TestMigrateUpgradesBetaSchema verifies that Migrate upgrades a database
// created by the 1.0.0-beta schema: the new column appears, existing rows read
// an empty user agent, and a second Migrate call stays idempotent.
func TestMigrateUpgradesBetaSchema(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	betaStatements, err := sqlfiles.LoadFile(sqlite.Migrations, "migrations", "0001_init.sql")
	if err != nil {
		t.Fatalf("load beta schema: %v", err)
	}
	for _, statement := range betaStatements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("apply beta statement: %v", err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.ExecContext(ctx,
		"INSERT INTO signet_users (id, email, email_verified, name, disabled, created_at, updated_at) VALUES ('user-1', 'user@example.com', 0, '', 0, ?, ?)", now, now)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_, err = db.ExecContext(ctx,
		"INSERT INTO signet_sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ('session-1', 'user-1', 'digest-1', ?, ?, ?, ?)",
		now, now, now, now)
	if err != nil {
		t.Fatalf("seed beta session: %v", err)
	}

	store := sqlite.New(db)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	var userAgent string
	if err := db.QueryRowContext(ctx, "SELECT user_agent FROM signet_sessions WHERE id = 'session-1'").Scan(&userAgent); err != nil {
		t.Fatalf("read user_agent: %v", err)
	}
	if userAgent != "" {
		t.Fatalf("pre-existing Session user_agent = %#v, want an empty string", userAgent)
	}

	session, err := store.SessionByHash(ctx, "digest-1")
	if err != nil {
		t.Fatalf("SessionByHash after upgrade: %v", err)
	}
	if session.UserAgent != "" {
		t.Fatalf("upgraded Session UserAgent = %#v, want an empty string", session.UserAgent)
	}
}
