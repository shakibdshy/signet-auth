package auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/mail"
	"github.com/shakibdshy/signet/internal/secret"
	"github.com/shakibdshy/signet/internal/token"
)

const defaultPasswordlessTTL = 5 * time.Minute

type magicLinkData struct {
	Email       string `json:"email"`
	Name        string `json:"name"`
	CallbackURL string `json:"callback_url"`
}

func (s *VerificationService) signUpAllowed() bool {
	if s.deps.Passwordless == nil || s.deps.Passwordless.AllowSignUp == nil {
		return true
	}
	return *s.deps.Passwordless.AllowSignUp
}

func (s *VerificationService) redirectAllowed(redirect string) bool {
	if redirect == "" {
		return false
	}
	if s.deps.Passwordless != nil && core.RedirectAllowed(redirect, s.deps.Passwordless.AllowedRedirects) {
		return true
	}
	if core.RedirectAllowed(redirect, s.deps.OAuthRedirects) {
		return true
	}
	base := strings.TrimRight(s.deps.AppURL, "/")
	if core.RedirectAllowed(redirect, []string{base}) {
		return true
	}
	baseURL, baseErr := url.Parse(base)
	target, targetErr := url.Parse(redirect)
	return baseErr == nil && targetErr == nil && target.Scheme == baseURL.Scheme && target.Host == baseURL.Host
}

// proofSubject is the rotation key for a proof issued before a User exists.
// It is never a User ID and never persisted as one.
func (s *VerificationService) proofSubject(email string) string {
	return secret.Digest("passwordless:" + email)
}

// SendMagicLink emails a single-use sign-in link. Unknown emails are
// silent-success when sign-up is disabled, so callers cannot enumerate Users
// and the endpoint cannot be used as an arbitrary mail relay.
func (s *VerificationService) SendMagicLink(ctx context.Context, in core.SendMagicLinkInput) error {
	email := normalizeEmail(in.Email)
	if email == "" {
		return core.ErrInvalidEmail
	}
	key := in.RateLimitKey
	if key == "" {
		key = email
	}
	if err := allow(ctx, s.deps.Limiter, "send-magic-link", key); err != nil {
		return err
	}
	user, err := s.deps.Store.UserByEmail(ctx, email)
	if err != nil && !errors.Is(err, core.ErrNotFound) {
		return err
	}
	known := err == nil
	if !known && !s.signUpAllowed() {
		// Equalize work with the registered path without issuing or sending.
		raw := secret.NewToken()
		_ = secret.Digest(raw)
		return nil
	}
	if in.CallbackURL != "" && !s.redirectAllowed(in.CallbackURL) {
		return core.ErrOAuthRedirectNotAllowed
	}

	subject := s.proofSubject(email)
	name := in.Name
	if known {
		subject = user.ID
		if name == "" {
			name = user.Name
		}
	}
	if err := s.deps.Store.DeleteTokensForUser(ctx, subject, core.TokenMagicLink); err != nil {
		return err
	}
	data, err := json.Marshal(magicLinkData{Email: email, Name: name, CallbackURL: in.CallbackURL})
	if err != nil {
		return err
	}
	raw, proof, err := s.deps.Tokens.IssueWithData(ctx, subject, core.TokenMagicLink, s.magicLinkTTL(), string(data))
	if err != nil {
		return err
	}
	link := s.emailLink("/verify-magic-link", raw)
	if in.CallbackURL != "" {
		link += "&callback_url=" + url.QueryEscape(in.CallbackURL)
	}
	templateData := core.TemplateData{Email: email, Name: name, URL: link, ExpiresAt: proof.ExpiresAt}
	message := mail.MagicLinkMessage(templateData)
	if custom, ok := s.deps.Templates.(core.MagicLinkTemplates); ok {
		message = custom.MagicLink(templateData)
	}
	if err := s.deps.Mailer.Send(ctx, message); err != nil {
		s.logWarn("magic_link_email_failed", "user_id", subject, "error", err)
		return err
	}
	s.logInfo("magic_link_sent", "user_id", subject)
	return nil
}

// VerifyMagicLink consumes a magic-link proof, marks the email verified and
// issues a Session. The embedded callback is authoritative; a query callback
// is accepted only when it matches.
func (s *VerificationService) VerifyMagicLink(ctx context.Context, in core.VerifyMagicLinkInput) (*core.SignInResult, error) {
	if in.Token == "" {
		return nil, core.ErrTokenInvalid
	}
	key := in.RateLimitKey
	if key == "" {
		key = "local"
	}
	if err := allow(ctx, s.deps.Limiter, "verify-magic-link", key); err != nil {
		return nil, err
	}
	rawData, err := token.ParseData(in.Token)
	if err != nil {
		return nil, core.ErrTokenInvalid
	}
	var data magicLinkData
	if err := json.Unmarshal([]byte(rawData), &data); err != nil || data.Email == "" {
		return nil, core.ErrTokenInvalid
	}
	if in.CallbackURL != "" && in.CallbackURL != data.CallbackURL {
		return nil, core.ErrOAuthRedirectNotAllowed
	}
	if data.CallbackURL != "" && !s.redirectAllowed(data.CallbackURL) {
		return nil, core.ErrOAuthRedirectNotAllowed
	}
	if _, err := s.deps.Tokens.Consume(ctx, core.TokenMagicLink, in.Token); err != nil {
		return nil, err
	}
	result, err := s.finishPasswordlessSignIn(ctx, data.Email, data.Name)
	if err != nil {
		return nil, err
	}
	s.logInfo("magic_link_sign_in", "user_id", result.User.ID)
	return result, nil
}

// finishPasswordlessSignIn resolves or creates the User after a proof has been
// consumed, marks the email verified and creates a Session.
func (s *VerificationService) finishPasswordlessSignIn(ctx context.Context, email, name string) (*core.SignInResult, error) {
	user, err := s.deps.Store.UserByEmail(ctx, email)
	if err != nil && !errors.Is(err, core.ErrNotFound) {
		return nil, err
	}
	if errors.Is(err, core.ErrNotFound) {
		if !s.signUpAllowed() {
			return nil, core.ErrTokenInvalid
		}
		now := s.deps.Clock.Now()
		user = &core.User{
			ID: secret.NewID(), Email: email, Name: name,
			EmailVerified: true, CreatedAt: now, UpdatedAt: now,
		}
		if err := s.deps.Store.CreateUser(ctx, user); err != nil {
			return nil, err
		}
		if s.deps.OnSignUp != nil {
			s.deps.OnSignUp(ctx, user)
		}
	} else {
		if user.Disabled {
			return nil, core.ErrInvalidCredentials
		}
		if !user.EmailVerified {
			user.EmailVerified = true
			user.UpdatedAt = s.deps.Clock.Now()
			if err := s.deps.Store.UpdateUser(ctx, user); err != nil {
				return nil, err
			}
		}
	}
	sessionToken, err := s.deps.CreateSession(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return &core.SignInResult{User: user, SessionToken: sessionToken}, nil
}

// newOTP returns a uniformly distributed six-digit numeric code.
func newOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// SendEmailOTP emails a six-digit sign-in code. Unknown emails are
// silent-success when sign-up is disabled, as with magic links.
func (s *VerificationService) SendEmailOTP(ctx context.Context, in core.SendEmailOTPInput) error {
	email := normalizeEmail(in.Email)
	if email == "" {
		return core.ErrInvalidEmail
	}
	key := in.RateLimitKey
	if key == "" {
		key = email
	}
	if err := allow(ctx, s.deps.Limiter, "send-otp", key); err != nil {
		return err
	}
	user, err := s.deps.Store.UserByEmail(ctx, email)
	if err != nil && !errors.Is(err, core.ErrNotFound) {
		return err
	}
	known := err == nil
	code, err := newOTP()
	if err != nil {
		return err
	}
	expiresAt := s.deps.Clock.Now().Add(s.otpTTL())
	if !known && !s.signUpAllowed() {
		// Equalize work without issuing or sending a proof.
		_ = secret.Digest(email + ":" + code)
		return nil
	}
	subject := s.proofSubject(email)
	name := in.Name
	if known {
		subject = user.ID
		if name == "" {
			name = user.Name
		}
	}
	if err := s.deps.Store.DeleteTokensForUser(ctx, subject, core.TokenEmailOTP); err != nil {
		return err
	}
	now := s.deps.Clock.Now()
	token := &core.Token{
		ID: secret.NewID(), UserID: subject, Kind: core.TokenEmailOTP,
		Hash: secret.Digest(email + ":" + code), ExpiresAt: expiresAt, CreatedAt: now,
	}
	if err := s.deps.Store.CreateToken(ctx, token); err != nil {
		return err
	}
	templateData := core.TemplateData{Email: email, Name: name, Code: code, ExpiresAt: expiresAt}
	message := mail.EmailOTPMessage(templateData)
	if custom, ok := s.deps.Templates.(core.EmailOTPTemplates); ok {
		message = custom.EmailOTP(templateData)
	}
	if err := s.deps.Mailer.Send(ctx, message); err != nil {
		s.logWarn("email_otp_failed", "user_id", subject, "error", err)
		return err
	}
	s.logInfo("email_otp_sent", "user_id", subject)
	return nil
}

// VerifyEmailOTP consumes the code and issues a Session. The limiter is
// consulted first so a wrong guess is throttled without burning the proof.
func (s *VerificationService) VerifyEmailOTP(ctx context.Context, in core.VerifyEmailOTPInput) (*core.SignInResult, error) {
	email := normalizeEmail(in.Email)
	if email == "" || len(in.Code) != 6 {
		return nil, core.ErrTokenInvalid
	}
	client := in.RateLimitKey
	if client == "" {
		client = "local"
	}
	if err := allow(ctx, s.deps.Limiter, "verify-otp", email+"|"+client); err != nil {
		return nil, err
	}
	for _, char := range in.Code {
		if char < '0' || char > '9' {
			return nil, core.ErrTokenInvalid
		}
	}
	proof := email + ":" + in.Code
	if _, err := s.deps.Tokens.Consume(ctx, core.TokenEmailOTP, proof); err != nil {
		return nil, err
	}
	result, err := s.finishPasswordlessSignIn(ctx, email, "")
	if err != nil {
		return nil, err
	}
	s.logInfo("email_otp_sign_in", "user_id", result.User.ID)
	return result, nil
}

func (s *VerificationService) otpTTL() time.Duration {
	if s.deps.Passwordless != nil && s.deps.Passwordless.OTPTTL > 0 {
		return s.deps.Passwordless.OTPTTL
	}
	return defaultPasswordlessTTL
}

func (s *VerificationService) magicLinkTTL() time.Duration {
	if s.deps.Passwordless != nil && s.deps.Passwordless.MagicLinkTTL > 0 {
		return s.deps.Passwordless.MagicLinkTTL
	}
	return defaultPasswordlessTTL
}
