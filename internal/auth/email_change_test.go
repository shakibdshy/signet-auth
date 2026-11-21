package auth

import "testing"

func TestNormalizeEmailForChange(t *testing.T) {
	got := normalizeEmail("  New@Example.COM ")
	if got != "new@example.com" {
		t.Fatalf("normalizeEmail = %q", got)
	}
}
