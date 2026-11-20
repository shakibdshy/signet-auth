// Package bcrypt provides a bcrypt PasswordHasher adapter for applications
// that need to match an existing users table. Argon2id remains the default.
package bcrypt

import (
	"context"
	"errors"

	xbcrypt "golang.org/x/crypto/bcrypt"
)

// DefaultCost is the bcrypt cost used when Hasher.Cost is zero.
const DefaultCost = 12

// Hasher implements signet.PasswordHasher using bcrypt.
type Hasher struct {
	Cost int
}

func (h Hasher) cost() int {
	if h.Cost == 0 {
		return DefaultCost
	}
	return h.Cost
}

// Hash returns a bcrypt verifier for a password.
func (h Hasher) Hash(ctx context.Context, password string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	encoded, err := xbcrypt.GenerateFromPassword([]byte(password), h.cost())
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// Verify reports whether password matches a bcrypt verifier.
func (h Hasher) Verify(ctx context.Context, encoded, password string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	err := xbcrypt.CompareHashAndPassword([]byte(encoded), []byte(password))
	if errors.Is(err, xbcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	return err == nil, err
}

// NeedsRehash reports whether a verifier is missing or uses another cost.
func (h Hasher) NeedsRehash(encoded string) bool {
	cost, err := xbcrypt.Cost([]byte(encoded))
	return err != nil || cost != h.cost()
}
