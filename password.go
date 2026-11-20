package signet

import "context"

// PasswordHasher stores and verifies password verifiers. The encoded value
// returned by Hash carries its algorithm and parameters so it can be upgraded.
type PasswordHasher interface {
	// Hash returns an encoded verifier for a password.
	Hash(context.Context, string) (string, error)
	// Verify reports whether a password matches an encoded verifier.
	Verify(context.Context, string, string) (bool, error)
	// NeedsRehash reports whether an encoded verifier should be upgraded.
	NeedsRehash(string) bool
}
