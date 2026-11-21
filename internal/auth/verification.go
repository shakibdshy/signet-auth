package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
	"github.com/shakibdshy/signet/internal/token"
)

const (
	verificationTokenTTL = 24 * time.Hour
	resetTokenTTL        = time.Hour
)

// VerificationDependencies holds the collaborators for the verification and
// reset flows.
type VerificationDependencies struct {
	Store     core.Store
	Tokens    *token.Service
	Mailer    core.Mailer
	Templates core.EmailTemplates
	Clock     core.Clock
	Limiter   core.RateLimiter
	Logger    *slog.Logger
	AppURL    string
	Password  core.PasswordConfig
	Hasher    core.PasswordHasher
}

// VerificationService implements email verification and password reset.
type VerificationService struct{ deps VerificationDependencies }

// NewVerification returns a VerificationService.
func NewVerification(deps VerificationDependencies) *VerificationService {
	return &VerificationService{deps: deps}
}

func (s *VerificationService) logInfo(msg string, attrs ...any) {
	s.deps.Logger.Info(msg, append([]any{"at", s.deps.Clock.Now()}, attrs...)...)
}

func (s *VerificationService) logWarn(msg string, attrs ...any) {
	s.deps.Logger.Warn(msg, append([]any{"at", s.deps.Clock.Now()}, attrs...)...)
}

func (s *VerificationService) emailLink(path, raw string) string {
	return strings.TrimRight(s.deps.AppURL, "/") + path + "?token=" + raw
}

// SendVerification sends a verification email. It succeeds for unknown emails
// so callers cannot enumerate registered Users.
func (s *VerificationService) SendVerification(ctx context.Context, in core.SendVerificationInput) error {
	email := normalizeEmail(in.Email)
	if email == "" {
		return core.ErrInvalidEmail
	}
	if err := allow(ctx, s.deps.Limiter, "verification_send", in.RateLimitKey); err != nil {
		return err
	}
	user, err := s.deps.Store.UserByEmail(ctx, email)
	if errors.Is(err, core.ErrNotFound) {
		// Equalize work with the registered-email path without sending mail.
		// Mail transport time itself remains a signal; eliminating that needs
		// queued delivery, which is outside this phase.
		raw := secret.NewToken()
		_ = secret.Digest(raw)
		_ = s.deps.Templates.VerifyEmail(core.TemplateData{
			Email: email, ExpiresAt: s.deps.Clock.Now().Add(verificationTokenTTL),
		})
		return nil
	}
	if err != nil {
		return err
	}
	return s.SendVerificationForUser(ctx, user)
}

// SendVerificationForUser issues a verification proof and mails it.
func (s *VerificationService) SendVerificationForUser(ctx context.Context, user *core.User) error {
	if err := s.deps.Store.DeleteTokensForUser(ctx, user.ID, core.TokenVerifyEmail); err != nil {
		return err
	}
	raw, proof, err := s.deps.Tokens.Issue(ctx, user.ID, core.TokenVerifyEmail, verificationTokenTTL)
	if err != nil {
		return err
	}
	message := s.deps.Templates.VerifyEmail(core.TemplateData{
		Email: user.Email, Name: user.Name,
		URL: s.emailLink("/verify", raw), ExpiresAt: proof.ExpiresAt,
	})
	if err := s.deps.Mailer.Send(ctx, message); err != nil {
		s.logWarn("verification_email_failed", "user_id", user.ID, "error", err)
		return err
	}
	s.logInfo("verification_sent", "user_id", user.ID)
	return nil
}

// VerifyEmail consumes a verification Token and marks its User verified.
func (s *VerificationService) VerifyEmail(ctx context.Context, in core.VerifyEmailInput) error {
	if in.Token == "" {
		return core.ErrTokenInvalid
	}
	if err := allow(ctx, s.deps.Limiter, "verification", in.RateLimitKey); err != nil {
		return err
	}
	proof, err := s.deps.Tokens.Consume(ctx, core.TokenVerifyEmail, in.Token)
	if err != nil {
		return err
	}
	user, err := s.deps.Store.UserByID(ctx, proof.UserID)
	if err != nil {
		return err
	}
	user.EmailVerified = true
	if err := s.deps.Store.UpdateUser(ctx, user); err != nil {
		return err
	}
	s.logInfo("email_verified", "user_id", user.ID)
	return nil
}

// SendPasswordReset sends a reset email. It succeeds for unknown emails so
// callers cannot enumerate registered Users.
func (s *VerificationService) SendPasswordReset(ctx context.Context, in core.SendPasswordResetInput) error {
	email := normalizeEmail(in.Email)
	if email == "" {
		return core.ErrInvalidEmail
	}
	if err := allow(ctx, s.deps.Limiter, "password_reset_send", in.RateLimitKey); err != nil {
		return err
	}
	user, err := s.deps.Store.UserByEmail(ctx, email)
	if errors.Is(err, core.ErrNotFound) {
		// Equalize work with the registered-email path without sending mail.
		// Mail transport time itself remains a signal; eliminating that needs
		// queued delivery, which is outside this phase.
		raw := secret.NewToken()
		_ = secret.Digest(raw)
		_ = s.deps.Templates.ResetPassword(core.TemplateData{
			Email: email, ExpiresAt: s.deps.Clock.Now().Add(resetTokenTTL),
		})
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.deps.Store.DeleteTokensForUser(ctx, user.ID, core.TokenResetPassword); err != nil {
		return err
	}
	raw, proof, err := s.deps.Tokens.Issue(ctx, user.ID, core.TokenResetPassword, resetTokenTTL)
	if err != nil {
		return err
	}
	message := s.deps.Templates.ResetPassword(core.TemplateData{
		Email: user.Email, Name: user.Name,
		URL: s.emailLink("/reset", raw), ExpiresAt: proof.ExpiresAt,
	})
	if err := s.deps.Mailer.Send(ctx, message); err != nil {
		s.logWarn("password_reset_email_failed", "user_id", user.ID, "error", err)
		return err
	}
	s.logInfo("password_reset_sent", "user_id", user.ID)
	return nil
}

// ChangePasswordInput validation is pure so its edge cases can be unit tested.
func validateChangePassword(in core.ChangePasswordInput, minLength, maxLength int) error {
	if in.UserID == "" || in.CurrentPassword == "" || in.NewPassword == "" {
		return core.ErrInvalidCredentials
	}
	if len(in.NewPassword) < minLength {
		return core.ErrPasswordTooShort
	}
	if len(in.NewPassword) > maxLength {
		return core.ErrPasswordTooLong
	}
	return nil
}

// ChangePassword replaces an authenticated User's credential verifier after
// revoking every Session and Token of that User.
func (s *VerificationService) ChangePassword(ctx context.Context, in core.ChangePasswordInput) error {
	if err := validateChangePassword(in, s.deps.Password.MinLength, s.deps.Password.MaxLength); err != nil {
		return err
	}
	if err := allow(ctx, s.deps.Limiter, "change_password", in.RateLimitKey); err != nil {
		return err
	}
	user, err := s.deps.Store.UserByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	account, err := s.deps.Store.AccountByProvider(ctx, credentialProvider, user.ID)
	if err != nil {
		return err
	}
	ok, err := s.deps.Hasher.Verify(ctx, account.PasswordHash, in.CurrentPassword)
	if err != nil {
		return err
	}
	if !ok {
		return core.ErrInvalidCredentials
	}
	for _, kind := range []core.TokenKind{
		core.TokenVerifyEmail, core.TokenResetPassword, core.TokenOAuthLink,
		core.TokenRefresh, core.TokenOAuthState,
	} {
		if err := s.deps.Store.DeleteTokensForUser(ctx, user.ID, kind); err != nil {
			return err
		}
	}
	if err := s.deps.Store.DeleteSessionsForUser(ctx, user.ID); err != nil {
		return err
	}
	encoded, err := s.deps.Hasher.Hash(ctx, in.NewPassword)
	if err != nil {
		return err
	}
	updated := *account
	updated.PasswordHash = encoded
	if err := s.deps.Store.UpdateAccount(ctx, &updated); err != nil {
		return err
	}
	s.logInfo("password_changed", "user_id", user.ID)
	message := s.deps.Templates.PasswordChanged(core.TemplateData{Email: user.Email, Name: user.Name})
	if err := s.deps.Mailer.Send(ctx, message); err != nil {
		s.logWarn("password_changed_notification_failed", "user_id", user.ID, "error", err)
	}
	return nil
}

// ResetPassword consumes a reset Token and replaces the credential verifier.
func (s *VerificationService) ResetPassword(ctx context.Context, in core.ResetPasswordInput) error {
	if in.Token == "" {
		return core.ErrTokenInvalid
	}
	if len(in.NewPassword) < s.deps.Password.MinLength {
		return core.ErrPasswordTooShort
	}
	if len(in.NewPassword) > s.deps.Password.MaxLength {
		return core.ErrPasswordTooLong
	}
	if err := allow(ctx, s.deps.Limiter, "password_reset", in.RateLimitKey); err != nil {
		return err
	}
	proof, err := s.deps.Tokens.Consume(ctx, core.TokenResetPassword, in.Token)
	if err != nil {
		return err
	}
	user, err := s.deps.Store.UserByID(ctx, proof.UserID)
	if err != nil {
		return err
	}
	account, err := s.deps.Store.AccountByProvider(ctx, credentialProvider, user.ID)
	if err != nil {
		return err
	}
	// OWASP Forgot Password Cheat Sheet: a successful reset must invalidate
	// every outstanding reset Token and every Session, so a stolen link or a
	// Session established before the reset cannot grant access afterwards.
	// Revocation runs before the verifier changes and its errors are returned:
	// reporting success while credentials remain live would be worse than
	// retrying the reset.
	if err := s.deps.Store.DeleteTokensForUser(ctx, user.ID, core.TokenResetPassword); err != nil {
		return err
	}
	if err := s.deps.Store.DeleteSessionsForUser(ctx, user.ID); err != nil {
		return err
	}
	encoded, err := s.deps.Hasher.Hash(ctx, in.NewPassword)
	if err != nil {
		return err
	}
	updated := *account
	updated.PasswordHash = encoded
	if err := s.deps.Store.UpdateAccount(ctx, &updated); err != nil {
		return err
	}
	s.logInfo("password_reset", "user_id", user.ID)

	message := s.deps.Templates.PasswordChanged(core.TemplateData{Email: user.Email, Name: user.Name})
	if err := s.deps.Mailer.Send(ctx, message); err != nil {
		s.logWarn("password_changed_notification_failed", "user_id", user.ID, "error", err)
	}
	return nil
}
