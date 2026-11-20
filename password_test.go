package signet_test

import (
	"context"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
)

func TestArgon2idHasherRoundTrip(t *testing.T) {
	var hasher signet.PasswordHasher = signet.Argon2idHasher{}
	encoded, err := hasher.Hash(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$") {
		t.Fatalf("encoded verifier = %q, want an argon2id PHC string", encoded)
	}
	ok, err := hasher.Verify(context.Background(), encoded, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("Verify(correct) = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = hasher.Verify(context.Background(), encoded, "wrong password")
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestArgon2idHasherParametersTravelWithVerifier(t *testing.T) {
	fast := signet.Argon2idHasher{Time: 1, Memory: 8192, Threads: 1, KeyLen: 16, SaltLen: 8}
	encoded, err := fast.Hash(context.Background(), "password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, err := fast.Verify(context.Background(), encoded, "password")
	if err != nil || !ok {
		t.Fatalf("Verify with same params = (%v, %v), want (true, nil)", ok, err)
	}
	if !(signet.Argon2idHasher{}).NeedsRehash(encoded) {
		t.Error("default hasher should flag a verifier with non-default parameters")
	}
	if fast.NeedsRehash(encoded) {
		t.Error("hasher should accept a verifier produced with its own parameters")
	}
}

func TestArgon2idHasherSaltLengthAffectsRehash(t *testing.T) {
	shortSalt := signet.Argon2idHasher{SaltLen: 8}
	longSalt := signet.Argon2idHasher{SaltLen: 16}
	encoded, err := shortSalt.Hash(context.Background(), "password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !longSalt.NeedsRehash(encoded) {
		t.Error("a change in salt length must be treated as a parameter change")
	}
}

func TestArgon2idHasherRejectsMalformedVerifier(t *testing.T) {
	ok, err := (signet.Argon2idHasher{}).Verify(context.Background(), "not-a-verifier", "password")
	if err == nil || ok {
		t.Fatalf("Verify(malformed) = (%v, %v), want (false, error)", ok, err)
	}
}
