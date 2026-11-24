package bcrypt_test

import (
	"context"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/hash/bcrypt"
)

func TestHasherImplementsPasswordHasher(t *testing.T) {
	var hasher signet.PasswordHasher = bcrypt.Hasher{}
	encoded, err := hasher.Hash(context.Background(), "password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, err := hasher.Verify(context.Background(), encoded, "password")
	if err != nil || !ok {
		t.Fatalf("Verify(correct) = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = hasher.Verify(context.Background(), encoded, "wrong")
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = (%v, %v), want (false, nil)", ok, err)
	}
	if hasher.NeedsRehash(encoded) {
		t.Error("freshly produced verifier should not need rehash")
	}
}
