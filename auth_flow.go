package signet

import (
	"context"
	"strings"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
)

const credentialProvider = "credential"

// dummyPassword is hashed once at client construction for timing parity.
//
//nolint:gosec // G101: fixed timing-equalization input, not a credential.
const dummyPassword = "signet-anti-enumeration-dummy"

// SignUpInput is the input to a sign-up.
type SignUpInput = core.SignUpInput

// SignUpResult is the outcome of a successful sign-up.
type SignUpResult = core.SignUpResult

// SignInInput is the input to a sign-in.
type SignInInput = core.SignInInput

// SignInResult is the outcome of a successful sign-in.
type SignInResult = core.SignInResult

// SignOutInput is the input to a sign-out.
type SignOutInput = core.SignOutInput

// SignUp creates a User and its credential Account, returning the new User.
func (c *Client) SignUp(ctx context.Context, in SignUpInput) (*SignUpResult, error) {
	return c.auth.SignUp(ctx, in)
}

// SignIn verifies a password, rehashes a stale verifier, creates a Session and
// returns its raw Session token. Failures are deliberately generic so callers
// cannot tell whether an email is registered.
func (c *Client) SignIn(ctx context.Context, in SignInInput) (*SignInResult, error) {
	return c.auth.SignIn(ctx, in)
}

// SignOut revokes the Session identified by a Session token. Unknown or
// already-revoked tokens are a successful no-op so clients need no special
// handling for repeated logouts.
func (c *Client) SignOut(ctx context.Context, in SignOutInput) error {
	return c.auth.SignOut(ctx, in)
}

func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func redactedUser(user *User) *User {
	redactedCopy := *user
	redactedCopy.Email = ""
	redactedCopy.Name = ""
	return &redactedCopy
}

func (c *Client) allow(ctx context.Context, endpoint, key string) error {
	if key == "" {
		key = "local"
	}
	allowed, err := c.cfg.RateLimiter.Allow(ctx, endpoint+"|"+key)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrRateLimited
	}
	return nil
}

func newID() string { return secret.NewID() }
