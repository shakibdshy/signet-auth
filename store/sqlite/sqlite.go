// Package sqlite provides a pure-Go SQLite implementation of signet.Store.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/sqlfiles"
)

// Migrations contains the default schema, applied explicitly by Migrate.
//
//go:embed migrations/*.sql
var Migrations embed.FS

// Store implements signet.Store on a caller-owned database.
type Store struct {
	db *sql.DB
}

var _ signet.Store = (*Store)(nil)

// New returns a Store backed by db. The caller owns the database's lifecycle.
// For foreign-key enforcement on every pooled connection, open the database
// with the driver's foreign_keys pragma enabled in the DSN.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Migrate applies the embedded default schema. It is not part of signet.Store.
// Every statement is idempotent, so repeated calls are safe.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return err
	}
	statements, err := sqlfiles.Load(Migrations, "migrations")
	if err != nil {
		return err
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

// CreateUser implements the corresponding signet.Store method.
func (s *Store) CreateUser(ctx context.Context, user *signet.User) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO signet_users (id, email, email_verified, name, disabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		user.ID, user.Email, boolInt(user.EmailVerified), user.Name, boolInt(user.Disabled),
		formatTime(user.CreatedAt), formatTime(user.UpdatedAt))
	return err
}

// UserByID implements the corresponding signet.Store method.
func (s *Store) UserByID(ctx context.Context, id string) (*signet.User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		"SELECT id, email, email_verified, name, disabled, created_at, updated_at FROM signet_users WHERE id = ?", id))
}

// UserByEmail implements the corresponding signet.Store method.
func (s *Store) UserByEmail(ctx context.Context, email string) (*signet.User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		"SELECT id, email, email_verified, name, disabled, created_at, updated_at FROM signet_users WHERE email = ?", email))
}

// UpdateUser implements the corresponding signet.Store method.
func (s *Store) UpdateUser(ctx context.Context, user *signet.User) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE signet_users SET email = ?, email_verified = ?, name = ?, disabled = ?, updated_at = ? WHERE id = ?",
		user.Email, boolInt(user.EmailVerified), user.Name, boolInt(user.Disabled), formatTime(user.UpdatedAt), user.ID)
	return err
}

// DeleteUser implements the corresponding signet.Store method.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM signet_users WHERE id = ?", id)
	return err
}

// CreateAccount implements the corresponding signet.Store method.
func (s *Store) CreateAccount(ctx context.Context, account *signet.Account) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO signet_accounts (id, user_id, provider, provider_user_id, email, email_verified, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		account.ID, account.UserID, account.Provider, account.ProviderUserID, account.Email,
		boolInt(account.EmailVerified), account.PasswordHash, formatTime(account.CreatedAt))
	return err
}

// AccountsForUser implements the corresponding signet.Store method.
func (s *Store) AccountsForUser(ctx context.Context, userID string) ([]*signet.Account, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, user_id, provider, provider_user_id, email, email_verified, password_hash, created_at FROM signet_accounts WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var accounts []*signet.Account
	for rows.Next() {
		account, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

// AccountByProvider implements the corresponding signet.Store method.
func (s *Store) AccountByProvider(ctx context.Context, provider, providerUserID string) (*signet.Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx,
		"SELECT id, user_id, provider, provider_user_id, email, email_verified, password_hash, created_at FROM signet_accounts WHERE provider = ? AND provider_user_id = ?",
		provider, providerUserID))
}

// UpdateAccount implements the corresponding signet.Store method.
func (s *Store) UpdateAccount(ctx context.Context, account *signet.Account) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE signet_accounts SET email = ?, email_verified = ?, password_hash = ? WHERE id = ?",
		account.Email, boolInt(account.EmailVerified), account.PasswordHash, account.ID)
	return err
}

// DeleteAccount implements the corresponding signet.Store method.
func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM signet_accounts WHERE id = ?", id)
	return err
}

// CreateSession implements the corresponding signet.Store method.
func (s *Store) CreateSession(ctx context.Context, session *signet.Session) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO signet_sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		session.ID, session.UserID, session.TokenHash, formatTime(session.CreatedAt), formatTime(session.LastSeenAt),
		formatTime(session.IdleExpiresAt), formatTime(session.AbsoluteExpiresAt), formatTimePtr(session.RevokedAt))
	return err
}

// SessionByHash implements the corresponding signet.Store method.
func (s *Store) SessionByHash(ctx context.Context, hash string) (*signet.Session, error) {
	return scanSession(s.db.QueryRowContext(ctx,
		"SELECT id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at FROM signet_sessions WHERE token_hash = ?", hash))
}

// TouchSession implements the corresponding signet.Store method.
func (s *Store) TouchSession(ctx context.Context, id string, idleExpiresAt time.Time) error {
	result, err := s.db.ExecContext(ctx, "UPDATE signet_sessions SET idle_expires_at = ? WHERE id = ?", formatTime(idleExpiresAt), id)
	if err != nil {
		return err
	}
	return requireRows(result)
}

// DeleteSession implements the corresponding signet.Store method.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM signet_sessions WHERE id = ?", id)
	return err
}

// DeleteSessionsForUser implements the corresponding signet.Store method.
func (s *Store) DeleteSessionsForUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM signet_sessions WHERE user_id = ?", userID)
	return err
}

// ListSessionsForUser implements the corresponding signet.Store method.
func (s *Store) ListSessionsForUser(ctx context.Context, userID string) ([]*signet.Session, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at FROM signet_sessions WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var sessions []*signet.Session
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// CreateToken implements the corresponding signet.Store method.
func (s *Store) CreateToken(ctx context.Context, token *signet.Token) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO signet_tokens (id, user_id, kind, hash, expires_at, used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		token.ID, token.UserID, string(token.Kind), token.Hash, formatTime(token.ExpiresAt), formatTimePtr(token.UsedAt), formatTime(token.CreatedAt))
	return err
}

// ConsumeToken implements the corresponding signet.Store method.
func (s *Store) ConsumeToken(ctx context.Context, kind signet.TokenKind, hash string) (*signet.Token, error) {
	now := formatTime(time.Now())
	return scanToken(s.db.QueryRowContext(ctx,
		"UPDATE signet_tokens SET used_at = ? WHERE kind = ? AND hash = ? AND used_at IS NULL RETURNING id, user_id, kind, hash, expires_at, used_at, created_at",
		now, string(kind), hash))
}

// TokenByHash implements the corresponding signet.Store method.
func (s *Store) TokenByHash(ctx context.Context, kind signet.TokenKind, hash string) (*signet.Token, error) {
	return scanToken(s.db.QueryRowContext(ctx,
		"SELECT id, user_id, kind, hash, expires_at, used_at, created_at FROM signet_tokens WHERE kind = ? AND hash = ?", string(kind), hash))
}

// DeleteTokensForUser implements the corresponding signet.Store method.
func (s *Store) DeleteTokensForUser(ctx context.Context, userID string, kind signet.TokenKind) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM signet_tokens WHERE user_id = ? AND kind = ?", userID, string(kind))
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (*signet.User, error) {
	var user signet.User
	var verified, disabled int
	var created, updated string
	err := row.Scan(&user.ID, &user.Email, &verified, &user.Name, &disabled, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, signet.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	user.EmailVerified, user.Disabled = intBool(verified), intBool(disabled)
	user.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	user.UpdatedAt, err = parseTime(updated)
	return &user, err
}

func scanAccount(row scanner) (*signet.Account, error) {
	var account signet.Account
	var verified int
	var created string
	err := row.Scan(&account.ID, &account.UserID, &account.Provider, &account.ProviderUserID,
		&account.Email, &verified, &account.PasswordHash, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, signet.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	account.EmailVerified = intBool(verified)
	account.CreatedAt, err = parseTime(created)
	return &account, err
}

func scanSession(row scanner) (*signet.Session, error) {
	var session signet.Session
	var created, lastSeen, idle, absolute string
	var revoked sql.NullString
	err := row.Scan(&session.ID, &session.UserID, &session.TokenHash, &created, &lastSeen, &idle, &absolute, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, signet.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	for _, pair := range []struct {
		target *time.Time
		value  string
	}{
		{&session.CreatedAt, created}, {&session.LastSeenAt, lastSeen},
		{&session.IdleExpiresAt, idle}, {&session.AbsoluteExpiresAt, absolute},
	} {
		parsed, err := parseTime(pair.value)
		if err != nil {
			return nil, err
		}
		*pair.target = parsed
	}
	if revoked.Valid {
		parsed, err := parseTime(revoked.String)
		if err != nil {
			return nil, err
		}
		session.RevokedAt = &parsed
	}
	return &session, nil
}

func scanToken(row scanner) (*signet.Token, error) {
	var token signet.Token
	var kind, expires, created string
	var used sql.NullString
	err := row.Scan(&token.ID, &token.UserID, &kind, &token.Hash, &expires, &used, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, signet.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	token.Kind = signet.TokenKind(kind)
	if token.ExpiresAt, err = parseTime(expires); err != nil {
		return nil, err
	}
	if token.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if used.Valid {
		parsed, err := parseTime(used.String)
		if err != nil {
			return nil, err
		}
		token.UsedAt = &parsed
	}
	return &token, nil
}

func requireRows(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return signet.ErrNotFound
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func intBool(value int) bool { return value != 0 }

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func formatTimePtr(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatTime(*value)
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, value)
}
