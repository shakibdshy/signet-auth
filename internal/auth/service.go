// Package auth implements Signet's email/password flows.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/shakibdshy/signet/internal/audit"
	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
	"github.com/shakibdshy/signet/internal/token"
)

const credentialProvider = "credential"

// dummyPassword is hashed once at construction so unknown-email sign-ins do
// comparable work. It is never logged.
//
//nolint:gosec // G101: fixed timing-equalization input, not a credential.
const dummyPassword = "signet-anti-enumeration-dummy"

// Dependencies holds the resolved configuration and cross-module callbacks
// the auth service needs.
type Dependencies struct {
	Store                    core.Store
	Hasher                   core.PasswordHasher
	Limiter                  core.RateLimiter
	Clock                    core.Clock
	Logger                   *slog.Logger
	Password                 core.PasswordConfig
	Username                 *core.UsernameConfig
	BreachChecker            core.BreachChecker
	CaptchaVerifier          core.CaptchaVerifier
	CaptchaEndpoints         []string
	AuditSink                core.AuditSink
	RequireVerifiedEmail     bool
	SendVerificationOnSignUp bool
	OnSignUp                 func(context.Context, *core.User)
	OnSignIn                 func(context.Context, *core.User)
	SendVerification         func(context.Context, *core.User) error
	CreateSession            func(context.Context, string) (string, error)
	AutoSignInAfterSignUp    bool
	RevokeSession            func(context.Context, string) error
	FlushSessions            func(context.Context)
	IsSessionFresh           func(context.Context, string, time.Duration) (bool, error)
	FreshWindow              time.Duration
	Tokens                   *token.Service
	TOTPStore                core.TOTPStore
	TOTPKey                  []byte
	TOTP                     *core.TOTPConfig
	AppURL                   string
	DummyVerifier            string
}

// Service implements the email/password flows.
type Service struct{ deps Dependencies }

// New returns an auth Service.
func New(deps Dependencies) *Service { return &Service{deps: deps} }

func (s *Service) logInfo(msg string, attrs ...any) {
	s.deps.Logger.Info(msg, append([]any{"at", s.deps.Clock.Now()}, attrs...)...)
}

func (s *Service) logWarn(msg string, attrs ...any) {
	s.deps.Logger.Warn(msg, append([]any{"at", s.deps.Clock.Now()}, attrs...)...)
}

func allow(ctx context.Context, limiter core.RateLimiter, endpoint, key string) error {
	if key == "" {
		key = "local"
	}
	allowed, err := limiter.Allow(ctx, endpoint+"|"+key)
	if err != nil {
		return err
	}
	if !allowed {
		return core.ErrRateLimited
	}
	return nil
}

func (s *Service) allow(ctx context.Context, endpoint, key string) error {
	return allow(ctx, s.deps.Limiter, endpoint, key)
}

func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func redacted(user *core.User) *core.User {
	redactedCopy := *user
	redactedCopy.Email = ""
	redactedCopy.Name = ""
	return &redactedCopy
}

func (s *Service) dummyVerify(ctx context.Context, password string) {
	if s.deps.DummyVerifier == "" {
		return
	}
	_, _ = s.deps.Hasher.Verify(ctx, s.deps.DummyVerifier, password)
}

func (s *Service) rehashIfNeeded(ctx context.Context, account *core.Account, password, userID string) {
	if !s.deps.Hasher.NeedsRehash(account.PasswordHash) {
		return
	}
	rehashed, err := s.deps.Hasher.Hash(ctx, password)
	if err != nil {
		s.logWarn("rehash_failed", "user_id", userID, "error", err)
		return
	}
	updated := *account
	updated.PasswordHash = rehashed
	if err := s.deps.Store.UpdateAccount(ctx, &updated); err != nil {
		s.logWarn("rehash_failed", "user_id", userID, "error", err)
		return
	}
	s.logInfo("rehash", "user_id", userID)
}

// SignUp creates a User and its credential Account.
func (s *Service) SignUp(ctx context.Context, in core.SignUpInput) (*core.SignUpResult, error) {
	email := normalizeEmail(in.Email)
	if email == "" {
		return nil, core.ErrInvalidEmail
	}
	if len(in.Password) < s.deps.Password.MinLength {
		return nil, core.ErrPasswordTooShort
	}
	if len(in.Password) > s.deps.Password.MaxLength {
		return nil, core.ErrPasswordTooLong
	}
	if err := s.allow(ctx, "signup", in.RateLimitKey); err != nil {
		return nil, err
	}
	if err := checkCaptcha(ctx, s.deps.CaptchaVerifier, s.deps.CaptchaEndpoints, "signup", in.CaptchaToken, in.CaptchaRemoteIP); err != nil {
		return nil, err
	}
	if _, err := s.deps.Store.UserByEmail(ctx, email); err == nil {
		return nil, core.ErrEmailAlreadyExists
	} else if !errors.Is(err, core.ErrNotFound) {
		return nil, err
	}
	var username string
	if in.Username != "" {
		var err error
		username, err = s.claimUsername(ctx, in.Username)
		if err != nil {
			return nil, err
		}
	}

	if err := checkBreach(ctx, s.deps.BreachChecker, in.Password); err != nil {
		return nil, err
	}
	encoded, err := s.deps.Hasher.Hash(ctx, in.Password)
	if err != nil {
		return nil, err
	}
	now := s.deps.Clock.Now()
	user := &core.User{ID: secret.NewID(), Email: email, Name: in.Name, CreatedAt: now, UpdatedAt: now}
	if err := s.deps.Store.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	account := &core.Account{
		ID: secret.NewID(), UserID: user.ID, Provider: credentialProvider,
		ProviderUserID: user.ID, Email: email, PasswordHash: encoded, CreatedAt: now,
	}
	if err := s.deps.Store.CreateAccount(ctx, account); err != nil {
		_ = s.deps.Store.DeleteUser(ctx, user.ID)
		return nil, err
	}
	if username != "" {
		usernameAccount := &core.Account{
			ID: secret.NewID(), UserID: user.ID, Provider: usernameProvider,
			ProviderUserID: username, Email: email, CreatedAt: now,
		}
		if err := s.deps.Store.CreateAccount(ctx, usernameAccount); err != nil {
			_ = s.deps.Store.DeleteAccount(ctx, account.ID)
			_ = s.deps.Store.DeleteUser(ctx, user.ID)
			return nil, err
		}
	}
	s.logInfo("sign_up", "user_id", user.ID)
	audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.SignUp, UserID: user.ID, Outcome: "success"})
	s.deps.OnSignUp(ctx, redacted(user))
	if s.deps.SendVerificationOnSignUp {
		if err := s.deps.SendVerification(ctx, user); err != nil {
			return nil, err
		}
	}
	result := &core.SignUpResult{User: user}
	if s.deps.AutoSignInAfterSignUp && (user.EmailVerified || !s.deps.RequireVerifiedEmail) {
		token, err := s.deps.CreateSession(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		result.SessionToken = token
		s.deps.OnSignIn(ctx, redacted(user))
		audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{
			Name: audit.SignInSuccess, UserID: user.ID, Outcome: "success",
			Metadata: map[string]string{"method": "email"},
		})
	}
	return result, nil
}

// SignIn verifies a password, rehashes if needed and creates a Session.
// A Username may be supplied instead of an email; both use the same generic
// failure path so callers cannot enumerate Users.
func (s *Service) SignIn(ctx context.Context, in core.SignInInput) (*core.SignInResult, error) {
	email := normalizeEmail(in.Email)
	if (email == "" && in.Username == "") || (email != "" && in.Username != "") {
		return nil, core.ErrInvalidEmail
	}
	if len(in.Password) < s.deps.Password.MinLength {
		return nil, core.ErrPasswordTooShort
	}
	if len(in.Password) > s.deps.Password.MaxLength {
		return nil, core.ErrPasswordTooLong
	}
	if err := s.allow(ctx, "signin", in.RateLimitKey); err != nil {
		return nil, err
	}
	if err := checkCaptcha(ctx, s.deps.CaptchaVerifier, s.deps.CaptchaEndpoints, "signin", in.CaptchaToken, in.CaptchaRemoteIP); err != nil {
		return nil, err
	}
	var user *core.User
	var err error
	method := "password"
	if in.Username != "" {
		method = "username"
	}
	if email != "" {
		user, err = s.deps.Store.UserByEmail(ctx, email)
	} else {
		user, err = s.findUserByUsername(ctx, in.Username)
	}
	if err != nil || user.Disabled {
		s.dummyVerify(ctx, in.Password)
		s.logInfo("sign_in_failure", "reason", "unavailable")
		audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.SignInFailure, Outcome: "blocked", Metadata: map[string]string{"reason": "unavailable"}})
		return nil, core.ErrInvalidCredentials
	}
	account, err := s.deps.Store.AccountByProvider(ctx, credentialProvider, user.ID)
	if err != nil {
		s.dummyVerify(ctx, in.Password)
		s.logInfo("sign_in_failure", "reason", "unavailable")
		audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.SignInFailure, Outcome: "blocked", Metadata: map[string]string{"reason": "unavailable"}})
		return nil, core.ErrInvalidCredentials
	}
	ok, err := s.deps.Hasher.Verify(ctx, account.PasswordHash, in.Password)
	if err != nil {
		return nil, err
	}
	if !ok {
		s.logInfo("sign_in_failure", "reason", "mismatch")
		audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.SignInFailure, Outcome: "blocked", Metadata: map[string]string{"reason": "mismatch"}})
		return nil, core.ErrInvalidCredentials
	}
	if s.deps.RequireVerifiedEmail && !user.EmailVerified {
		s.logInfo("sign_in_failure", "reason", "unverified")
		audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.SignInFailure, Outcome: "blocked", Metadata: map[string]string{"reason": "unverified"}})
		return nil, core.ErrEmailNotVerified
	}
	s.rehashIfNeeded(ctx, account, in.Password, user.ID)
	if s.deps.TOTPStore != nil {
		state, stateErr := s.deps.TOTPStore.Get(ctx, user.ID)
		if stateErr == nil && state.Verified {
			challenge, _, issueErr := s.deps.Tokens.IssueWithData(ctx, user.ID, core.TokenTwoFactor, challengeTTL, method)
			if issueErr != nil {
				return nil, issueErr
			}
			s.logInfo("two_factor_challenge_issued", "user_id", user.ID)
			return &core.SignInResult{User: user, TwoFactorChallenge: challenge, LastSignInMethod: method}, nil
		}
		if stateErr != nil && !errors.Is(stateErr, core.ErrNotFound) {
			return nil, stateErr
		}
	}
	sessionToken, err := s.deps.CreateSession(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	s.logInfo("sign_in_success", "user_id", user.ID)
	audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.SignInSuccess, UserID: user.ID, Outcome: "success"})
	s.deps.OnSignIn(ctx, redacted(user))
	return &core.SignInResult{User: user, SessionToken: sessionToken, LastSignInMethod: method}, nil
}

// SignOut revokes the Session identified by a Session token.
func (s *Service) SignOut(ctx context.Context, in core.SignOutInput) error {
	if in.SessionToken == "" {
		return nil
	}
	session, err := s.deps.Store.SessionByHash(ctx, secret.Digest(in.SessionToken))
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.deps.RevokeSession(ctx, session.ID); err != nil {
		return err
	}
	s.logInfo("sign_out", "user_id", session.UserID)
	audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.SignOut, UserID: session.UserID, SessionID: session.ID, Outcome: "success"})
	return nil
}
