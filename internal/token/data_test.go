package token_test

import (
	"context"
	"testing"

	"time"

	"github.com/shakibdshy/signet/internal/token"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/testutil"
)

func TestIssueWithDataRoundTrip(t *testing.T) {
	store := testutil.NewStore()
	clock := testutil.FixedClock{At: time.Now()}
	svc := token.New(store, clock)
	raw, proof, err := svc.IssueWithData(context.Background(), "user-1", core.TokenKind("change_email"), time.Hour, "new@example.com")
	if err != nil {
		t.Fatalf("IssueWithData: %v", err)
	}
	if proof.UserID != "user-1" {
		t.Fatalf("proof user = %q, want user-1", proof.UserID)
	}
	data, err := token.ParseData(raw)
	if err != nil || data != "new@example.com" {
		t.Fatalf("ParseData = %q, %v", data, err)
	}
	// Tampering with the embedded data must break the stored digest lookup.
	tampered := raw[:len(raw)-2] + "xx"
	if _, err := svc.Consume(context.Background(), core.TokenKind("change_email"), tampered); err == nil {
		t.Error("tampered proof was accepted")
	}
}
