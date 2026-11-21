package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
	"github.com/shakibdshy/signet/internal/session"
	"github.com/shakibdshy/signet/internal/testutil"
)

func TestIsFreshUsesCreatedAtNotLastSeen(t *testing.T) {
	store := testutil.NewStore()
	now := time.Now()
	clock := testutil.FixedClock{At: now}
	raw := secret.NewToken()
	store.Sessions["id"] = &core.Session{
		ID: "id", TokenHash: secret.Digest(raw),
		CreatedAt: now.Add(-time.Hour), LastSeenAt: now,
	}
	svc := session.New(store, clock, core.SessionConfig{FreshAge: 5 * time.Minute})
	fresh, err := svc.IsFresh(context.Background(), raw)
	if err != nil || fresh {
		t.Fatalf("fresh = %v, err = %v; want false", fresh, err)
	}

	store.Sessions["id"].CreatedAt = now.Add(-time.Minute)
	fresh, err = svc.IsFresh(context.Background(), raw)
	if err != nil || !fresh {
		t.Fatalf("fresh = %v, err = %v; want true", fresh, err)
	}
}
