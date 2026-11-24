// Package accountcontrol implements profile and password management operations.
package accountcontrol

import (
	"context"
	"errors"
	"log/slog"

	"github.com/shakibdshy/signet/internal/audit"
	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
	"github.com/shakibdshy/signet/internal/session"
)

const credentialProvider = "credential"

// Deps holds the collaborators for account control operations.
type Deps struct {
	Config   *core.Config
	Store    core.Store
	Sessions *session.Service
	Resolve  func(context.Context, string) (*core.User, error)
	Logger   *slog.Logger
}

// Service implements the public account control operations.
type Service struct{ deps Deps }

// New returns a Service.
func New(deps Deps) *Service { return &Service{deps: deps} }

func (s *Service) actor(ctx context.Context, inUserID, sessionToken string) (*core.User, error) {
	if inUserID == "" || sessionToken == "" || s.deps.Resolve == nil {
		return nil, core.ErrForbidden
	}
	actor, err := s.deps.Resolve(ctx, sessionToken)
	if err != nil || actor == nil || actor.ID != inUserID {
		return nil, core.ErrForbidden
	}
	fresh, err := s.deps.Sessions.IsFreshWithin(ctx, sessionToken, s.deps.Config.Accounts.FreshWindow)
	if err != nil || !fresh {
		return nil, core.ErrForbidden
	}
	return actor, nil
}

func (s *Service) emit(ctx context.Context, name, userID string) {
	audit.Emit(ctx, s.deps.Config.AuditSink, s.deps.Logger, core.AuditEvent{
		Name: name, UserID: userID, Outcome: "success",
	})
}

// UpdateUser changes safe profile fields for a signed-in User.
func (s *Service) UpdateUser(ctx context.Context, in core.UpdateUserInput) (*core.UserInfo, error) {
	user, err := s.actor(ctx, in.UserID, in.SessionToken)
	if err != nil {
		return nil, err
	}
	if stringsTrimmed(in.Name) != "" {
		user.Name = in.Name
	}
	user.UpdatedAt = s.deps.Config.Clock.Now()
	if err := s.deps.Store.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	s.emit(ctx, "user_updated", user.ID)
	return &core.UserInfo{ID: user.ID, Email: user.Email, Name: user.Name, Disabled: user.Disabled}, nil
}

func stringsTrimmed(value string) string {
	out := []rune(value)
	start := 0
	for start < len(out) && (out[start] == ' ' || out[start] == '\t' || out[start] == '\n') {
		start++
	}
	end := len(out)
	for end > start && (out[end-1] == ' ' || out[end-1] == '\t' || out[end-1] == '\n') {
		end--
	}
	return string(out[start:end])
}

// SetPassword creates a credential Account for a User who does not have one.
func (s *Service) SetPassword(ctx context.Context, in core.SetPasswordInput) error {
	user, err := s.actor(ctx, in.UserID, in.SessionToken)
	if err != nil {
		return err
	}
	if _, err := s.deps.Store.AccountByProvider(ctx, credentialProvider, user.ID); err == nil {
		return core.ErrInvalidCredentials
	} else if !errors.Is(err, core.ErrNotFound) {
		return err
	}
	if len(in.NewPassword) < s.deps.Config.Password.MinLength {
		return core.ErrPasswordTooShort
	}
	if len(in.NewPassword) > s.deps.Config.Password.MaxLength {
		return core.ErrPasswordTooLong
	}
	encoded, err := s.deps.Config.PasswordHasher.Hash(ctx, in.NewPassword)
	if err != nil {
		return err
	}
	account := &core.Account{
		ID: secret.NewID(), UserID: user.ID, Provider: credentialProvider,
		ProviderUserID: user.ID, Email: user.Email, PasswordHash: encoded,
	}
	if err := s.deps.Store.CreateAccount(ctx, account); err != nil {
		return err
	}
	if err := s.deps.Sessions.RevokeAll(ctx, user.ID); err != nil {
		return err
	}
	for _, kind := range core.AllTokenKinds {
		if err := s.deps.Store.DeleteTokensForUser(ctx, user.ID, kind); err != nil {
			return err
		}
	}
	s.emit(ctx, "password_set", user.ID)
	return nil
}

// VerifyPassword checks a password without creating a Session.
func (s *Service) VerifyPassword(ctx context.Context, in core.VerifyPasswordInput) (bool, error) {
	if in.UserID == "" || in.Password == "" {
		return false, nil
	}
	account, err := s.deps.Store.AccountByProvider(ctx, credentialProvider, in.UserID)
	if err != nil {
		return false, nil
	}
	ok, err := s.deps.Config.PasswordHasher.Verify(ctx, account.PasswordHash, in.Password)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// QueryAudit returns filtered Audit events through an optional query store.
func (s *Service) QueryAudit(ctx context.Context, sessionToken string, in core.AuditQueryInput) ([]*core.AuditEvent, error) {
	store, ok := s.deps.Config.AuditSink.(core.AuditQueryStore)
	if !ok || s.deps.Resolve == nil {
		return nil, core.ErrForbidden
	}
	user, err := s.deps.Resolve(ctx, sessionToken)
	if err != nil || user == nil {
		return nil, core.ErrForbidden
	}
	fresh, err := s.deps.Sessions.IsFreshWithin(ctx, sessionToken, s.deps.Config.Accounts.FreshWindow)
	if err != nil || !fresh {
		return nil, core.ErrForbidden
	}
	if in.Limit <= 0 || in.Limit > 100 {
		in.Limit = 100
	}
	events, err := store.Query(ctx, in)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		if stringsContainsSecret(event.Metadata) {
			return nil, core.ErrForbidden
		}
	}
	return events, nil
}

func stringsContainsSecret(metadata map[string]string) bool {
	for key := range metadata {
		lower := stringsToLower(key)
		if lower == "password" || lower == "token" || lower == "secret" {
			return true
		}
	}
	return false
}

func stringsToLower(value string) string {
	runes := []rune(value)
	for i, r := range runes {
		if r >= 'A' && r <= 'Z' {
			runes[i] = r + ('a' - 'A')
		}
	}
	return string(runes)
}
