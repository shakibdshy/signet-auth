package signet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/shakibdshy/signet/internal/core"
)

const credentialProvider = "credential"

// dummyPassword is hashed once at client construction for timing parity.
//
//nolint:gosec // G101: fixed timing-equalization input, not a credential.
const dummyPassword = "signet-anti-enumeration-dummy"

// SignUpInput is re-exported from core.
type SignUpInput = core.SignUpInput

// SignUpResult is re-exported from core.
type SignUpResult = core.SignUpResult

// SignInInput is re-exported from core.
type SignInInput = core.SignInInput

// SignInResult is re-exported from core.
type SignInResult = core.SignInResult

// SignOutInput is re-exported from core.
type SignOutInput = core.SignOutInput

// SignUp delegates to the auth module.
func (c *Client) SignUp(ctx context.Context, in SignUpInput) (*SignUpResult, error) {
	return c.auth.SignUp(ctx, in)
}

// SignIn delegates to the auth module.
func (c *Client) SignIn(ctx context.Context, in SignInInput) (*SignInResult, error) {
	return c.auth.SignIn(ctx, in)
}

// SignOut delegates to the auth module.
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

func newID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("signet: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(buf)
}
