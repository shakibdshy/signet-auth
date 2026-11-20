package signet

import (
	"github.com/shakibdshy/signet/internal/auth"
	"github.com/shakibdshy/signet/internal/core"
)

// PasswordHasher stores and verifies password verifiers. The encoded value
// returned by Hash carries its algorithm and parameters so it can be upgraded.
type PasswordHasher = core.PasswordHasher

// Argon2idHasher stores password verifiers as Argon2id PHC strings. Its zero
// value uses the OWASP-recommended parameters.
type Argon2idHasher = auth.Argon2idHasher
