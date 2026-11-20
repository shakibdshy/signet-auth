package postgres_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/store/conformance"
	"github.com/shakibdshy/signet/store/postgres"
)

func TestStorePassesConformance(t *testing.T) {
	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "postgres:16-alpine",
			Env: map[string]string{
				"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "test",
			},
			ExposedPorts: []string{"5432/tcp"},
			WaitingFor:   wait.ForListeningPort("5432/tcp"),
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

	store := postgres.New(pool)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	conformance.Run(t, func(t *testing.T) signet.Store {
		_, err := pool.Exec(ctx, "TRUNCATE signet_users, signet_accounts, signet_sessions, signet_tokens RESTART IDENTITY CASCADE")
		if err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return store
	})
}
