package core

import "testing"

func TestNormalizeEmailTrimsAndLowercases(t *testing.T) {
	if got := NormalizeEmail("  New@Example.COM "); got != "new@example.com" {
		t.Fatalf("NormalizeEmail = %q, want %q", got, "new@example.com")
	}
}

func TestAllTokenKindsCoversEveryDeclaredKind(t *testing.T) {
	declared := map[TokenKind]bool{
		TokenVerifyEmail: true, TokenChangeEmail: true, TokenDeleteUser: true, TokenResetPassword: true, TokenOAuthLink: true,
		TokenRefresh: true, TokenOAuthState: true, TokenMagicLink: true, TokenEmailOTP: true,
		TokenTwoFactor: true, TokenPasskeyRegistration: true, TokenPasskeyAuthentication: true,
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
