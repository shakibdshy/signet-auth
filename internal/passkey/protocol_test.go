package passkey

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/shakibdshy/signet-auth/internal/core"
)

func TestProtocolOptionsEnforcePolicy(t *testing.T) {
	p, err := NewProtocol(&core.PasskeysConfig{
		RPID: "example.com", RPOrigins: []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("NewProtocol: %v", err)
	}
	options, _, err := p.BeginRegistration(context.Background(), "user-1", "user@example.com", nil)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	var parsed struct {
		PublicKey struct {
			AuthenticatorSelection struct {
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
			Attestation string `json:"attestation"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &parsed); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	if parsed.PublicKey.AuthenticatorSelection.UserVerification != "required" {
		t.Fatalf("userVerification = %q, want required", parsed.PublicKey.AuthenticatorSelection.UserVerification)
	}
	if parsed.PublicKey.Attestation != "none" {
		t.Fatalf("attestation = %q, want none", parsed.PublicKey.Attestation)
	}
}
