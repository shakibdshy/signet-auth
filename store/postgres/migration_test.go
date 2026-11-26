package postgres_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/shakibdshy/signet-auth/internal/sqlfiles"
	"github.com/shakibdshy/signet-auth/store/postgres"
)

// TestMigrateUpgradesBetaSchema verifies that Migrate upgrades a database
// created by the 1.0.0-beta schema: the new column appears, existing rows read
// an empty user agent, and a second Migrate call stays idempotent.
func TestMigrateUpgradesBetaSchema(t *testing.T) {
	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "postgres:16-alpine",
			Env: map[string]string{
				"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "test",
			},
			ExposedPorts: []string{"5432/tcp"},
			WaitingFor:   wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
		},
		Started: true,
	})
	if err != nil {
		t.Skipf("Docker unavailable, skipping PostgreSQL integration test: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	dsn := fmt.Sprintf("postgres://test:test@%s:%s/test?sslmode=disable", host, port.Port())
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	for attempt := 0; attempt < 30; attempt++ {
		if err := pool.Ping(ctx); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	betaStatements, err := sqlfiles.LoadFile(postgres.Migrations, "migrations", "0001_init.sql")
	if err != nil {
		t.Fatalf("load beta schema: %v", err)
	}
	for _, statement := range betaStatements {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("apply beta statement: %v", err)
		}
	}
	_, err = pool.Exec(ctx,
		"INSERT INTO signet_users (id, email, email_verified, name, disabled, created_at, updated_at) VALUES ('user-1', 'user@example.com', FALSE, '', FALSE, NOW(), NOW())")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_, err = pool.Exec(ctx,
		"INSERT INTO signet_sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ('session-1', 'user-1', 'digest-1', NOW(), NOW(), NOW(), NOW())")
	if err != nil {
		t.Fatalf("seed beta session: %v", err)
	}

	store := postgres.New(pool)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	var userAgent string
	if err := pool.QueryRow(ctx, "SELECT user_agent FROM signet_sessions WHERE id = 'session-1'").Scan(&userAgent); err != nil {
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
