package core

import "testing"

func TestAllTokenKindsCoversEveryDeclaredKind(t *testing.T) {
	declared := map[TokenKind]bool{
		TokenVerifyEmail: true, TokenResetPassword: true, TokenOAuthLink: true,
		TokenRefresh: true, TokenOAuthState: true,
	}
	if len(AllTokenKinds) != len(declared) {
		t.Fatalf("AllTokenKinds has %d entries, want %d", len(AllTokenKinds), len(declared))
	}
	for _, kind := range AllTokenKinds {
		if !declared[kind] {
			t.Errorf("unexpected kind %q", kind)
		}
		delete(declared, kind)
	}
	for kind := range declared {
		t.Errorf("AllTokenKinds missing %q", kind)
	}
}
