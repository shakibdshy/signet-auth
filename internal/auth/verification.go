package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/shakibdshy/signet-auth/internal/audit"
	"github.com/shakibdshy/signet-auth/internal/core"
	"github.com/shakibdshy/signet-auth/internal/secret"
	"github.com/shakibdshy/signet-auth/internal/token"
)

const (
	verificationTokenTTL = 24 * time.Hour
	resetTokenTTL        = time.Hour
)

// VerificationDependencies holds the collaborators for the verification and
// reset flows.
type VerificationDependencies struct {
	Store            core.Store
	Tokens           *token.Service
	Mailer           core.Mailer
	Templates        core.EmailTemplates
	Clock            core.Clock
	Limiter          core.RateLimiter
	Logger           *slog.Logger
	AppURL           string
	PathPrefix       string
	Password         core.PasswordConfig
	Hasher           core.PasswordHasher
	Passwordless     *core.PasswordlessConfig
	OAuthRedirects   []string
	RedirectPatterns []string
	CreateSession    func(context.Context, string, string) (string, error)
	RevokeSessions   func(context.Context, string) error
	FlushSessions    func(context.Context)
	BreachChecker    core.BreachChecker
	CaptchaVerifier  core.CaptchaVerifier
	CaptchaEndpoints []string
	AuditSink        core.AuditSink
	FreshSession     func(context.Context, string) bool
	DeletePasskeys   func(context.Context, string) error
	OnSignIn         func(context.Context, *core.User)
	AutoSignIn       bool
}

// VerificationService implements email verification, password reset and
// passwordless sign-in.
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
	return strings.TrimRight(s.deps.AppURL, "/") + strings.TrimRight(s.deps.PathPrefix, "/") + path + "?token=" + raw
}

// SendVerification sends a verification email. It succeeds for unknown emails
// so callers cannot enumerate registered Users.
func (s *VerificationService) SendVerification(ctx context.Context, in core.SendVerificationInput) error {
	email := normalizeEmail(in.Email)
	if email == "" {
		return core.ErrInvalidEmail
	}
	if err := allow(ctx, s.deps.Limiter, "send-verification", in.RateLimitKey); err != nil {
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
	_, err := s.verify(ctx, in, false)
	return err
}

// VerifyEmailAndSignIn verifies a User and issues a Session when configured.
func (s *VerificationService) VerifyEmailAndSignIn(ctx context.Context, in core.VerifyEmailInput) (*core.VerifyEmailAndSignInResult, error) {
	return s.verify(ctx, in, true)
}

func (s *VerificationService) verify(ctx context.Context, in core.VerifyEmailInput, allowAutomatic bool) (*core.VerifyEmailAndSignInResult, error) {
	if in.Token == "" {
		return nil, core.ErrTokenInvalid
	}
	if err := allow(ctx, s.deps.Limiter, "verify-email", in.RateLimitKey); err != nil {
		return nil, err
	}
	proof, err := s.deps.Tokens.Consume(ctx, core.TokenVerifyEmail, in.Token)
	if err != nil {
		return nil, err
	}
	user, err := s.deps.Store.UserByID(ctx, proof.UserID)
	if err != nil {
		return nil, err
	}
	user.EmailVerified = true
	if err := s.deps.Store.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	s.logInfo("email_verified", "user_id", user.ID)
	audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.EmailVerified, UserID: user.ID, Outcome: "success"})
	result := &core.VerifyEmailAndSignInResult{User: user}
	if allowAutomatic && s.deps.AutoSignIn {
		token, err := s.issueAutomaticSession(ctx, user)
		if err != nil {
			return nil, err
		}
		result.SessionToken = token
	}
	return result, nil
}

func (s *VerificationService) issueAutomaticSession(ctx context.Context, user *core.User) (string, error) {
	token, err := s.deps.CreateSession(ctx, user.ID, "")
	if err != nil {
		return "", err
	}
	s.deps.OnSignIn(ctx, redacted(user))
	audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{
		Name: audit.SignInSuccess, UserID: user.ID, Outcome: "success",
		Metadata: map[string]string{"method": "email"},
	})
	return token, nil
}

// SendPasswordReset sends a reset email. It succeeds for unknown emails so
// callers cannot enumerate registered Users.
func (s *VerificationService) SendPasswordReset(ctx context.Context, in core.SendPasswordResetInput) error {
	email := normalizeEmail(in.Email)
	if email == "" {
		return core.ErrInvalidEmail
	}
	if err := allow(ctx, s.deps.Limiter, "send-password-reset", in.RateLimitKey); err != nil {
		return err
	}
	if err := checkCaptcha(ctx, s.deps.CaptchaVerifier, s.deps.CaptchaEndpoints, "send-password-reset", in.CaptchaToken, in.CaptchaRemoteIP); err != nil {
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

// RequestUserDeletion sends a single-use proof to the User's current email.
func (s *VerificationService) RequestUserDeletion(ctx context.Context, in core.RequestDeleteUserInput) error {
	if in.UserID == "" {
		return core.ErrInvalidCredentials
	}
	if in.SessionToken != "" && !s.freshProof(in.SessionToken) {
		return core.ErrForbidden
	}
	if err := allow(ctx, s.deps.Limiter, "request-account-deletion", in.RateLimitKey); err != nil {
		return err
	}
	user, err := s.deps.Store.UserByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	if err := s.deps.Store.DeleteTokensForUser(ctx, user.ID, core.TokenDeleteUser); err != nil {
		return err
	}
	ttl := 24 * time.Hour
	raw, _, err := s.deps.Tokens.Issue(ctx, user.ID, core.TokenDeleteUser, ttl)
	if err != nil {
		return err
	}
	data := core.TemplateData{Email: user.Email, Name: user.Name,
		URL: s.emailLink("/confirm-delete-user", raw), ExpiresAt: s.deps.Clock.Now().Add(ttl)}
	msg := s.deleteUserMessage(data)
	if err := s.deps.Mailer.Send(ctx, msg); err != nil {
		s.logWarn("delete_user_notification_failed", "user_id", user.ID, "error", err)
		return err
	}
	s.logInfo("delete_user_requested", "user_id", user.ID)
	return nil
}

// DeleteUser consumes the proof and removes the User's children explicitly
// before the User row, following ADR 0006.
func (s *VerificationService) DeleteUser(ctx context.Context, in core.ConfirmDeleteUserInput) error {
	if in.Token == "" {
		return core.ErrTokenInvalid
	}
	if err := allow(ctx, s.deps.Limiter, "confirm-account-deletion", in.RateLimitKey); err != nil {
		return err
	}
	proof, err := s.deps.Tokens.Consume(ctx, core.TokenDeleteUser, in.Token)
	if err != nil {
		return err
	}
	if err := s.deps.RevokeSessions(ctx, proof.UserID); err != nil {
		return err
	}
	for _, kind := range core.AllTokenKinds {
		if err := s.deps.Store.DeleteTokensForUser(ctx, proof.UserID, kind); err != nil {
			return err
		}
	}
	accounts, err := s.deps.Store.AccountsForUser(ctx, proof.UserID)
	if err != nil {
		return err
	}
	for _, account := range accounts {
		if err := s.deps.Store.DeleteAccount(ctx, account.ID); err != nil {
			return err
		}
	}
	if s.deps.DeletePasskeys != nil {
		if err := s.deps.DeletePasskeys(ctx, proof.UserID); err != nil {
			return err
		}
	}
	if err := s.deps.Store.DeleteUser(ctx, proof.UserID); err != nil {
		return err
	}
	s.logInfo("user_deleted", "user_id", proof.UserID)
	audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.UserDeleted, UserID: proof.UserID, Outcome: "success"})
	return nil
}

func (s *VerificationService) deleteUserMessage(data core.TemplateData) core.Message {
	if templates, ok := s.deps.Templates.(core.DeleteUserTemplates); ok {
		return templates.DeleteUser(data)
	}
	return core.Message{
		To: data.Email, Subject: "Confirm account deletion",
		TextBody: "Confirm deletion of your account:\n" + data.URL + "\n",
		HTMLBody: "<p>Confirm deletion: <a href=\"" + data.URL + "\">link</a></p>",
	}
}

// RequestEmailChange issues a single-use proof to the new address. The old
// address remains active until VerifyEmailChange succeeds.
func (s *VerificationService) RequestEmailChange(ctx context.Context, in core.ChangeEmailInput) error {
	if in.UserID == "" || (in.CurrentPassword == "" && !s.freshProof(in.SessionToken)) {
		return core.ErrInvalidCredentials
	}
	email := normalizeEmail(in.NewEmail)
	if !strings.Contains(email, "@") || strings.HasPrefix(email, "@") || strings.HasSuffix(email, "@") {
		return core.ErrInvalidEmail
	}
	if err := allow(ctx, s.deps.Limiter, "change-email", in.RateLimitKey); err != nil {
		return err
	}
	user, err := s.deps.Store.UserByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	if in.CurrentPassword != "" {
		// A fresh passkey Session substitutes for this proof when no password is supplied.
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
	}
	if existing, err := s.deps.Store.UserByEmail(ctx, email); err == nil {
		if existing.ID != user.ID {
			return core.ErrInvalidEmail
		}
		return core.ErrInvalidEmail
	}
	if err := s.deps.Store.DeleteTokensForUser(ctx, user.ID, core.TokenChangeEmail); err != nil {
		return err
	}
	raw, _, err := s.deps.Tokens.IssueWithData(ctx, user.ID, core.TokenChangeEmail, verificationTokenTTL, email)
	if err != nil {
		return err
	}
	data := core.TemplateData{
		Email: email, Name: user.Name,
		URL: s.emailLink("/verify-email-change", raw), ExpiresAt: s.deps.Clock.Now().Add(verificationTokenTTL),
	}
	msg := s.changeEmailMessage(data)
	if err := s.deps.Mailer.Send(ctx, msg); err != nil {
		s.logWarn("email_change_notification_failed", "user_id", user.ID, "error", err)
		return err
	}
	s.logInfo("email_change_requested", "user_id", user.ID)
	return nil
}

// VerifyEmailChange consumes the proof and commits the new address.
func (s *VerificationService) VerifyEmailChange(ctx context.Context, in core.VerifyEmailChangeInput) error {
	if in.Token == "" {
		return core.ErrTokenInvalid
	}
	if err := allow(ctx, s.deps.Limiter, "verify-change-email", in.RateLimitKey); err != nil {
		return err
	}
	proof, err := s.deps.Tokens.Consume(ctx, core.TokenChangeEmail, in.Token)
	if err != nil {
		return err
	}
	email, err := token.ParseData(in.Token)
	if err != nil {
		return core.ErrTokenInvalid
	}
	if existing, err := s.deps.Store.UserByEmail(ctx, email); err == nil && existing.ID != proof.UserID {
		return core.ErrEmailAlreadyExists
	}
	user, err := s.deps.Store.UserByID(ctx, proof.UserID)
	if err != nil {
		return err
	}
	user.Email = email
	user.EmailVerified = false
	if err := s.deps.Store.UpdateUser(ctx, user); err != nil {
		return err
	}
	if s.deps.FlushSessions != nil {
		s.deps.FlushSessions(ctx)
	}
	s.logInfo("email_changed", "user_id", user.ID)
	audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.EmailChanged, UserID: user.ID, Outcome: "success"})
	return nil
}

func (s *VerificationService) changeEmailMessage(data core.TemplateData) core.Message {
	if templates, ok := s.deps.Templates.(core.EmailChangeTemplates); ok {
		return templates.ChangeEmail(data)
	}
	return core.Message{
		To: data.Email, Subject: "Verify your email change",
		TextBody: "Confirm your new email address:\n" + data.URL + "\n",
		HTMLBody: "<p>Confirm your new email address: <a href=\"" + data.URL + "\">link</a></p>",
	}
}

// ChangePasswordInput validation is pure so its edge cases can be unit tested.
func validateChangePassword(in core.ChangePasswordInput, minLength, maxLength int) error {
	if in.UserID == "" || in.CurrentPassword == "" {
		return core.ErrInvalidCredentials
	}
	if in.NewPassword == "" {
		return core.ErrPasswordTooShort
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
	if err := allow(ctx, s.deps.Limiter, "change-password", in.RateLimitKey); err != nil {
		return err
	}
	user, err := s.deps.Store.UserByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	account, err := s.deps.Store.AccountByProvider(ctx, credentialProvider, user.ID)
	if errors.Is(err, core.ErrNotFound) {
		return core.ErrInvalidCredentials
	}
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
	if err := checkBreach(ctx, s.deps.BreachChecker, in.NewPassword); err != nil {
		return err
	}
	for _, kind := range core.AllTokenKinds {
		if err := s.deps.Store.DeleteTokensForUser(ctx, user.ID, kind); err != nil {
			return err
		}
	}
	if err := s.deps.RevokeSessions(ctx, user.ID); err != nil {
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
	audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.PasswordChanged, UserID: user.ID, Outcome: "success"})
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
	if err := allow(ctx, s.deps.Limiter, "reset-password", in.RateLimitKey); err != nil {
		return err
	}
	if err := checkBreach(ctx, s.deps.BreachChecker, in.NewPassword); err != nil {
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
	newAccount := false
	if errors.Is(err, core.ErrNotFound) {
		// A passkey-only User has no credential Account; the emailed proof
		// creates the first one so recovery works after losing every passkey.
		account = &core.Account{ID: secret.NewID(), UserID: user.ID, Provider: credentialProvider, ProviderUserID: user.ID}
		newAccount = true
	} else if err != nil {
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
	if err := s.deps.RevokeSessions(ctx, user.ID); err != nil {
		return err
	}
	encoded, err := s.deps.Hasher.Hash(ctx, in.NewPassword)
	if err != nil {
		return err
	}
	updated := *account
	updated.PasswordHash = encoded
	if newAccount {
		if err := s.deps.Store.CreateAccount(ctx, &updated); err != nil {
			return err
		}
	} else if err := s.deps.Store.UpdateAccount(ctx, &updated); err != nil {
		return err
	}
	s.logInfo("reset-password", "user_id", user.ID)
	audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.ResetPassword, UserID: user.ID, Outcome: "success"})

	message := s.deps.Templates.PasswordChanged(core.TemplateData{Email: user.Email, Name: user.Name})
	if err := s.deps.Mailer.Send(ctx, message); err != nil {
		s.logWarn("password_changed_notification_failed", "user_id", user.ID, "error", err)
	}
	return nil
}

func (s *VerificationService) freshProof(raw string) bool {
	return s.deps.FreshSession != nil && raw != "" && s.deps.FreshSession(context.Background(), raw)
}
