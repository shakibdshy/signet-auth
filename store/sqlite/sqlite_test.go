package sqlite_test

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/store/conformance"
	"github.com/shakibdshy/signet-auth/store/sqlite"
)

func newStore(t *testing.T) *sqlite.Store {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.New(db)
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	return store
}

func TestStorePassesConformance(t *testing.T) {
	conformance.Run(t, func(t *testing.T) signet.Store { return newStore(t) })
}
