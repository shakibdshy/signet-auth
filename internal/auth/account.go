package auth

import (
	"context"

	"github.com/shakibdshy/signet/internal/core"
)

// ListAccounts returns the safe fields of a User's Accounts.
func (s *Service) ListAccounts(ctx context.Context, in core.ListAccountsInput) (*core.ListAccountsResult, error) {
	accounts, err := s.deps.Store.AccountsForUser(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	out := make([]*core.AccountInfo, 0, len(accounts))
	for _, account := range accounts {
		out = append(out, &core.AccountInfo{
			ID: account.ID, Provider: account.Provider, ProviderUserID: account.ProviderUserID,
			Email: account.Email, EmailVerified: account.EmailVerified, CreatedAt: account.CreatedAt,
		})
	}
	return &core.ListAccountsResult{Accounts: out}, nil
}

// UnlinkAccount removes one Account after proving a recent Session. A User is
// never allowed to drop below one Account, because a Second factor alone
// cannot sign in.
func (s *Service) UnlinkAccount(ctx context.Context, in core.UnlinkAccountInput) error {
	if in.UserID == "" || in.AccountID == "" {
		return core.ErrInvalidCredentials
	}
	if err := s.allow(ctx, "unlink-account", in.RateLimitKey); err != nil {
		return err
	}
	fresh, err := s.deps.IsSessionFresh(ctx, in.SessionToken, s.deps.FreshWindow)
	if err != nil || !fresh {
		return core.ErrSessionNotFresh
	}
	accounts, err := s.deps.Store.AccountsForUser(ctx, in.UserID)
	if err != nil {
		return err
	}
	if len(accounts) <= 1 {
		return core.ErrLastAccount
	}
	var found *core.Account
	for _, account := range accounts {
		if account.ID == in.AccountID {
			found = account
			break
		}
	}
	if found == nil || found.UserID != in.UserID {
		return core.ErrNotFound
	}
	if err := s.deps.Store.DeleteAccount(ctx, found.ID); err != nil {
		return err
	}
	if s.deps.FlushSessions != nil {
		s.deps.FlushSessions(ctx)
	}
	s.logInfo("account_unlinked", "user_id", in.UserID, "provider", found.Provider)
	return nil
}
