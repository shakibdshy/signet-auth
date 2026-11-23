// Package passkey implements passkeys as a first factor.
package passkey

import (
	"context"
	"log/slog"
	"time"

	"github.com/shakibdshy/signet/internal/audit"
	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/session"
	"github.com/shakibdshy/signet/internal/token"
)

const ceremonyTTL = 5 * time.Minute

// Deps holds the dependencies shared by passkey operations.
type Deps struct {
	Config  *core.Config
	Store   core.Store
	Tokens  tokenService
	Session *session.Service
	Logger  *slog.Logger
}

// tokenService is the subset of the Token service used by passkey ceremonies.
type tokenService interface {
	IssueWithData(ctx context.Context, userID string, kind core.TokenKind, ttl time.Duration, data string) (string, *core.Token, error)
	Consume(ctx context.Context, kind core.TokenKind, raw string) (*core.Token, error)
}

// Service implements the public passkey operations.
type Service struct {
	deps     Deps
	protocol core.PasskeyProtocol
}

// New returns a Service. A nil config yields a disabled service.
func New(deps Deps) *Service {
	var protocol core.PasskeyProtocol
	if deps.Config.Passkeys != nil {
		protocol = deps.Config.Passkeys.Protocol
		if protocol == nil {
			p, err := NewProtocol(deps.Config.Passkeys)
			if err == nil {
				protocol = p
			}
		}
	}
	return &Service{deps: deps, protocol: protocol}
}

// Enabled reports whether passkeys are configured.
func (s *Service) Enabled() bool {
	return s.deps.Config.Passkeys != nil && s.deps.Config.Passkeys.Store != nil && s.protocol != nil
}

func (s *Service) fresh(ctx context.Context, raw string) bool {
	if raw == "" {
		return false
	}
	fresh, err := s.deps.Session.IsFreshWithin(ctx, raw, s.deps.Config.Accounts.FreshWindow)
	return err == nil && fresh
}

func (s *Service) emit(ctx context.Context, name, userID string, metadata map[string]string) {
	audit.Emit(ctx, s.deps.Config.AuditSink, s.deps.Logger, core.AuditEvent{
		Name: name, UserID: userID, Outcome: "success", Metadata: metadata,
	})
}

func (s *Service) deny(ctx context.Context, userID, name string) {
	audit.Emit(ctx, s.deps.Config.AuditSink, s.deps.Logger, core.AuditEvent{
		Name: name, UserID: userID, Outcome: "denied",
	})
}

// BeginRegistration starts an enrollment ceremony for a signed-in User.
func (s *Service) BeginRegistration(ctx context.Context, in core.PasskeyRegistrationInput) (*core.PasskeyCeremonyResult, error) {
	if !s.Enabled() || !s.fresh(ctx, in.SessionToken) {
		return nil, core.ErrForbidden
	}
	user, err := s.deps.Store.UserByID(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	if s.deps.Config.RequireVerifiedEmail != nil && *s.deps.Config.RequireVerifiedEmail && !user.EmailVerified {
		return nil, core.ErrForbidden
	}
	credentials, err := s.deps.Config.Passkeys.Store.CredentialsByUser(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	options, data, err := s.protocol.BeginRegistration(ctx, user.ID, user.Email, credentials)
	if err != nil {
		return nil, err
	}
	raw, _, err := s.deps.Tokens.IssueWithData(ctx, user.ID, core.TokenPasskeyRegistration, ceremonyTTL, data)
	if err != nil {
		return nil, err
	}
	return &core.PasskeyCeremonyResult{Options: options, Token: raw}, nil
}

// FinishRegistration verifies the ceremony and stores the WebAuthn credential.
func (s *Service) FinishRegistration(ctx context.Context, in core.PasskeyFinishInput) error {
	if !s.Enabled() || !s.fresh(ctx, in.SessionToken) {
		return core.ErrForbidden
	}
	ceremony, err := s.deps.Tokens.Consume(ctx, core.TokenPasskeyRegistration, in.Token)
	if err != nil {
		return core.ErrTokenInvalid
	}
	data := ceremonyData(ctx, in.Token, ceremony, s)
	credential, err := s.protocol.FinishRegistration(ctx, data, in.Response)
	if err != nil {
		s.deny(ctx, ceremony.UserID, "passkey_registration_failed")
		return core.ErrTokenInvalid
	}
	credential.UserID = ceremony.UserID
	credential.CreatedAt = s.deps.Config.Clock.Now()
	if err := s.deps.Config.Passkeys.Store.CreateCredential(ctx, credential); err != nil {
		return err
	}
	s.emit(ctx, "passkey_enrolled", ceremony.UserID, map[string]string{"credential_id": credential.ID})
	return nil
}

// BeginLogin starts a discoverable authentication ceremony.
func (s *Service) BeginLogin(ctx context.Context) (*core.PasskeyCeremonyResult, error) {
	if !s.Enabled() {
		return nil, core.ErrForbidden
	}
	options, data, err := s.protocol.BeginLogin(ctx)
	if err != nil {
		return nil, err
	}
	raw, _, err := s.deps.Tokens.IssueWithData(ctx, "", core.TokenPasskeyAuthentication, ceremonyTTL, data)
	if err != nil {
		return nil, err
	}
	return &core.PasskeyCeremonyResult{Options: options, Token: raw}, nil
}

// FinishLogin verifies an assertion and creates a normal Session for the User.
func (s *Service) FinishLogin(ctx context.Context, in core.PasskeyFinishSignInInput) (*core.SignInResult, error) {
	if !s.Enabled() {
		return nil, core.ErrForbidden
	}
	ceremony, err := s.deps.Tokens.Consume(ctx, core.TokenPasskeyAuthentication, in.Token)
	if err != nil {
		return nil, core.ErrTokenInvalid
	}
	data := ceremonyData(ctx, in.Token, ceremony, s)
	userID, credential, err := s.protocol.FinishLogin(ctx, data, in.Response)
	if err != nil {
		s.deny(ctx, "", "passkey_assertion_failed")
		return nil, core.ErrTokenInvalid
	}
	if _, err := s.deps.Store.UserByID(ctx, userID); err != nil {
		return nil, core.ErrTokenInvalid
	}
	stored, err := s.deps.Config.Passkeys.Store.CredentialByID(ctx, credential.ID)
	if err == nil && stored.SignCount > credential.SignCount {
		s.emit(ctx, "passkey_sign_count_regression", userID, map[string]string{"credential_id": credential.ID})
	}
	credential.UserID = userID
	if err := s.deps.Config.Passkeys.Store.UpdateCredential(ctx, credential); err != nil {
		return nil, err
	}
	token, err := s.deps.Session.Create(ctx, userID)
	if err != nil {
		return nil, err
	}
	user, _ := s.deps.Store.UserByID(ctx, userID)
	result := &core.SignInResult{SessionToken: token, LastSignInMethod: "passkey", User: user}
	s.emit(ctx, "passkey_sign_in", userID, map[string]string{"credential_id": credential.ID})
	return result, nil
}

// List returns the safe fields of a User's passkeys.
func (s *Service) List(ctx context.Context, in core.PasskeyListInput) (*core.PasskeyListResult, error) {
	if !s.Enabled() || !s.fresh(ctx, in.SessionToken) {
		return nil, core.ErrForbidden
	}
	credentials, err := s.deps.Config.Passkeys.Store.CredentialsByUser(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	passkeys := make([]*core.PasskeyInfo, 0, len(credentials))
	for _, c := range credentials {
		passkeys = append(passkeys, &core.PasskeyInfo{
			ID: c.ID, AAGUID: c.AAGUID, SignCount: c.SignCount, CreatedAt: c.CreatedAt,
		})
	}
	return &core.PasskeyListResult{Passkeys: passkeys}, nil
}

// Delete revokes one of a User's passkeys.
func (s *Service) Delete(ctx context.Context, in core.PasskeyDeleteInput) error {
	if !s.Enabled() || !s.fresh(ctx, in.SessionToken) {
		return core.ErrForbidden
	}
	credential, err := s.deps.Config.Passkeys.Store.CredentialByID(ctx, in.CredentialID)
	if err != nil || credential.UserID != in.UserID {
		return core.ErrForbidden
	}
	if err := s.deps.Config.Passkeys.Store.DeleteCredential(ctx, in.CredentialID); err != nil {
		return err
	}
	s.emit(ctx, "passkey_deleted", in.UserID, map[string]string{"credential_id": in.CredentialID})
	return nil
}

// DeleteForUser removes every credential owned by a User.
func (s *Service) DeleteForUser(ctx context.Context, userID string) error {
	if !s.Enabled() {
		return nil
	}
	credentials, err := s.deps.Config.Passkeys.Store.CredentialsByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, c := range credentials {
		if err := s.deps.Config.Passkeys.Store.DeleteCredential(ctx, c.ID); err != nil {
			return err
		}
	}
	return nil
}

// ceremonyData returns the opaque data carried by a ceremony Token.
func ceremonyData(_ context.Context, raw string, _ *core.Token, _ *Service) string {
	data, err := token.ParseData(raw)
	if err != nil {
		return ""
	}
	return data
}
