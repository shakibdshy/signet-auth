package signet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

const credentialProvider = "credential"

// dummyPassword is hashed once at client construction so a sign-in for an
// unknown email costs the same as one for a real User. It is never logged.
//
//nolint:gosec // G101: this is a fixed timing-equalization input, not a credential.
const dummyPassword = "signet-anti-enumeration-dummy"

// SignUpInput is the input to a sign-up.
type SignUpInput struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	Name         string `json:"name"`
	RateLimitKey string `json:"-"`
}

// SignUpResult is the outcome of a successful sign-up.
type SignUpResult struct {
	User *User
}

// SignInInput is the input to a sign-in.
type SignInInput struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	RateLimitKey string `json:"-"`
}

// SignInResult is the outcome of a successful sign-in.
type SignInResult struct {
	User         *User
	SessionToken string
}

// SignOutInput is the input to a sign-out.
type SignOutInput struct {
	SessionToken string `json:"session_token"`
}

// SignUp creates a User and its credential Account, returning the new User.
func (c *Client) SignUp(ctx context.Context, in SignUpInput) (*SignUpResult, error) {
	email := normalizeEmail(in.Email)
	if email == "" {
		return nil, ErrInvalidEmail
	}
	if len(in.Password) < c.cfg.Password.MinLength {
		return nil, ErrPasswordTooShort
	}
	if len(in.Password) > c.cfg.Password.MaxLength {
		return nil, ErrPasswordTooLong
	}
	if err := c.allow(ctx, "signup", in.RateLimitKey); err != nil {
		return nil, err
	}
	if _, err := c.cfg.Store.UserByEmail(ctx, email); err == nil {
		return nil, ErrEmailAlreadyExists
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	encoded, err := c.cfg.PasswordHasher.Hash(ctx, in.Password)
	if err != nil {
		return nil, err
	}
	now := c.cfg.Clock.Now()
	user := &User{
		ID:        newID(),
		Email:     email,
		Name:      in.Name,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := c.cfg.Store.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	account := &Account{
		ID:             newID(),
		UserID:         user.ID,
		Provider:       credentialProvider,
		ProviderUserID: user.ID,
		Email:          email,
		PasswordHash:   encoded,
		CreatedAt:      now,
	}
	if err := c.cfg.Store.CreateAccount(ctx, account); err != nil {
		// Best-effort cleanup: without a transaction contract this cannot be
		// atomic across databases, which the adapters will address later.
		_ = c.cfg.Store.DeleteUser(ctx, user.ID)
		return nil, err
	}

	c.logInfo("sign_up", "user_id", user.ID)
	c.cfg.OnSignUp(ctx, redactedUser(user))
	if c.sendVerificationOnSignUp() {
		// A mail outage must not destroy a successfully created User; the
		// caller receives the error and can retry with SendVerification.
		if err := c.sendVerification(ctx, user); err != nil {
			return nil, err
		}
	}
	return &SignUpResult{User: user}, nil
}

// SignIn verifies a password, rehashes a stale verifier, creates a Session and
// returns its raw Session token. Failures are deliberately generic so callers
// cannot tell whether an email is registered.
func (c *Client) SignIn(ctx context.Context, in SignInInput) (*SignInResult, error) {
	email := normalizeEmail(in.Email)
	if email == "" {
		return nil, ErrInvalidEmail
	}
	if len(in.Password) < c.cfg.Password.MinLength {
		return nil, ErrPasswordTooShort
	}
	if len(in.Password) > c.cfg.Password.MaxLength {
		return nil, ErrPasswordTooLong
	}
	if err := c.allow(ctx, "signin", in.RateLimitKey); err != nil {
		return nil, err
	}

	user, err := c.cfg.Store.UserByEmail(ctx, email)
	if err != nil || user.Disabled {
		c.dummyVerify(ctx, in.Password)
		c.logInfo("sign_in_failure", "reason", "unavailable")
		return nil, ErrInvalidCredentials
	}
	account, err := c.cfg.Store.AccountByProvider(ctx, credentialProvider, user.ID)
	if err != nil {
		c.dummyVerify(ctx, in.Password)
		c.logInfo("sign_in_failure", "reason", "unavailable")
		return nil, ErrInvalidCredentials
	}

	ok, err := c.cfg.PasswordHasher.Verify(ctx, account.PasswordHash, in.Password)
	if err != nil {
		return nil, err
	}
	if !ok {
		c.logInfo("sign_in_failure", "reason", "mismatch")
		return nil, ErrInvalidCredentials
	}
	if c.requireVerifiedEmail() && !user.EmailVerified {
		c.logInfo("sign_in_failure", "reason", "unverified")
		return nil, ErrEmailNotVerified
	}

	c.rehashIfNeeded(ctx, account, in.Password, user.ID)

	token, digest := newRawSecret()
	now := c.cfg.Clock.Now()
	session := &Session{
		ID:                newID(),
		UserID:            user.ID,
		TokenHash:         digest,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(c.cfg.Session.IdleTimeout),
		AbsoluteExpiresAt: now.Add(c.cfg.Session.AbsoluteTimeout),
	}
	if err := c.cfg.Store.CreateSession(ctx, session); err != nil {
		return nil, err
	}
	c.logInfo("sign_in_success", "user_id", user.ID)
	c.cfg.OnSignIn(ctx, redactedUser(user))
	return &SignInResult{User: user, SessionToken: token}, nil
}

func (c *Client) rehashIfNeeded(ctx context.Context, account *Account, password, userID string) {
	if !c.cfg.PasswordHasher.NeedsRehash(account.PasswordHash) {
		return
	}
	rehashed, err := c.cfg.PasswordHasher.Hash(ctx, password)
	if err != nil {
		c.logWarn("rehash_failed", "user_id", userID, "error", err)
		return
	}
	updated := *account
	updated.PasswordHash = rehashed
	if err := c.cfg.Store.UpdateAccount(ctx, &updated); err != nil {
		c.logWarn("rehash_failed", "user_id", userID, "error", err)
		return
	}
	c.logInfo("rehash", "user_id", userID)
}

// SignOut revokes the Session identified by a Session token. Unknown or
// already-revoked tokens are a successful no-op so clients need no special
// handling for repeated logouts.
func (c *Client) SignOut(ctx context.Context, in SignOutInput) error {
	if in.SessionToken == "" {
		return nil
	}
	session, err := c.cfg.Store.SessionByHash(ctx, digestSecret(in.SessionToken))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := c.cfg.Store.DeleteSession(ctx, session.ID); err != nil {
		return err
	}
	c.logInfo("sign_out", "user_id", session.UserID)
	return nil
}

func (c *Client) dummyVerify(ctx context.Context, password string) {
	if c.dummyVerifier == "" {
		return
	}
	_, _ = c.cfg.PasswordHasher.Verify(ctx, c.dummyVerifier, password)
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

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func newID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing means the platform cannot produce safe IDs; there
		// is no acceptable fallback for a security library.
		panic("signet: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

func redactedUser(user *User) *User {
	redacted := *user
	redacted.Email = ""
	redacted.Name = ""
	return &redacted
}
