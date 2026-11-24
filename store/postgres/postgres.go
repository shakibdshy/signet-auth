// Package postgres provides a PostgreSQL implementation of signet.Store.
package postgres

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/sqlfiles"
)

// Migrations contains the default schema, applied explicitly by Migrate.
//
//go:embed migrations/*.sql
var Migrations embed.FS

// Store implements signet.Store on a caller-owned connection pool.
type Store struct {
	pool *pgxpool.Pool
}

var _ signet.Store = (*Store)(nil)

// New returns a Store backed by pool. The caller owns the pool's lifecycle.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Migrate applies the embedded default schema. It is not part of signet.Store.
// Every statement is idempotent, so repeated calls are safe.
func (s *Store) Migrate(ctx context.Context) error {
	statements, err := sqlfiles.Load(Migrations, "migrations")
	if err != nil {
		return err
	}
	for _, statement := range statements {
		if _, err := s.pool.Exec(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

// CreateUser implements the corresponding signet.Store method.
func (s *Store) CreateUser(ctx context.Context, user *signet.User) error {
	_, err := s.pool.Exec(ctx,
		"INSERT INTO signet_users (id, email, email_verified, name, disabled, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		user.ID, user.Email, user.EmailVerified, user.Name, user.Disabled, user.CreatedAt, user.UpdatedAt)
	return err
}

// UserByID implements the corresponding signet.Store method.
func (s *Store) UserByID(ctx context.Context, id string) (*signet.User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		"SELECT id, email, email_verified, name, disabled, created_at, updated_at FROM signet_users WHERE id = $1", id))
}

// UserByEmail implements the corresponding signet.Store method.
func (s *Store) UserByEmail(ctx context.Context, email string) (*signet.User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		"SELECT id, email, email_verified, name, disabled, created_at, updated_at FROM signet_users WHERE email = $1", email))
}

// UpdateUser implements the corresponding signet.Store method.
func (s *Store) UpdateUser(ctx context.Context, user *signet.User) error {
	tag, err := s.pool.Exec(ctx,
		"UPDATE signet_users SET email = $1, email_verified = $2, name = $3, disabled = $4, updated_at = $5 WHERE id = $6",
		user.Email, user.EmailVerified, user.Name, user.Disabled, user.UpdatedAt, user.ID)
	return requireRows(tag.RowsAffected(), err)
}

// DeleteUser implements the corresponding signet.Store method.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM signet_users WHERE id = $1", id)
	return err
}

// CreateAccount implements the corresponding signet.Store method.
func (s *Store) CreateAccount(ctx context.Context, account *signet.Account) error {
	_, err := s.pool.Exec(ctx,
		"INSERT INTO signet_accounts (id, user_id, provider, provider_user_id, email, email_verified, password_hash, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		account.ID, account.UserID, account.Provider, account.ProviderUserID, account.Email,
		account.EmailVerified, account.PasswordHash, account.CreatedAt)
	return err
}

// AccountsForUser implements the corresponding signet.Store method.
func (s *Store) AccountsForUser(ctx context.Context, userID string) ([]*signet.Account, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT id, user_id, provider, provider_user_id, email, email_verified, password_hash, created_at FROM signet_accounts WHERE user_id = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
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
	return scanAccount(s.pool.QueryRow(ctx,
		"SELECT id, user_id, provider, provider_user_id, email, email_verified, password_hash, created_at FROM signet_accounts WHERE provider = $1 AND provider_user_id = $2",
		provider, providerUserID))
}

// UpdateAccount implements the corresponding signet.Store method.
func (s *Store) UpdateAccount(ctx context.Context, account *signet.Account) error {
	tag, err := s.pool.Exec(ctx,
		"UPDATE signet_accounts SET email = $1, email_verified = $2, password_hash = $3 WHERE id = $4",
		account.Email, account.EmailVerified, account.PasswordHash, account.ID)
	return requireRows(tag.RowsAffected(), err)
}

// DeleteAccount implements the corresponding signet.Store method.
func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM signet_accounts WHERE id = $1", id)
	return err
}

// CreateSession implements the corresponding signet.Store method.
func (s *Store) CreateSession(ctx context.Context, session *signet.Session) error {
	_, err := s.pool.Exec(ctx,
		"INSERT INTO signet_sessions (id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		session.ID, session.UserID, session.TokenHash, session.CreatedAt, session.LastSeenAt,
		session.IdleExpiresAt, session.AbsoluteExpiresAt, session.RevokedAt)
	return err
}

// SessionByHash implements the corresponding signet.Store method.
func (s *Store) SessionByHash(ctx context.Context, hash string) (*signet.Session, error) {
	return scanSession(s.pool.QueryRow(ctx,
		"SELECT id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at FROM signet_sessions WHERE token_hash = $1", hash))
}

// TouchSession implements the corresponding signet.Store method.
func (s *Store) TouchSession(ctx context.Context, id string, idleExpiresAt time.Time) error {
	tag, err := s.pool.Exec(ctx, "UPDATE signet_sessions SET idle_expires_at = $1 WHERE id = $2", idleExpiresAt, id)
	return requireRows(tag.RowsAffected(), err)
}

// DeleteSession implements the corresponding signet.Store method.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM signet_sessions WHERE id = $1", id)
	return err
}

// DeleteSessionsForUser implements the corresponding signet.Store method.
func (s *Store) DeleteSessionsForUser(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM signet_sessions WHERE user_id = $1", userID)
	return err
}

// ListSessionsForUser implements the corresponding signet.Store method.
func (s *Store) ListSessionsForUser(ctx context.Context, userID string) ([]*signet.Session, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at FROM signet_sessions WHERE user_id = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
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
	_, err := s.pool.Exec(ctx,
		"INSERT INTO signet_tokens (id, user_id, kind, hash, expires_at, used_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		token.ID, token.UserID, string(token.Kind), token.Hash, token.ExpiresAt, token.UsedAt, token.CreatedAt)
	return err
}

// ConsumeToken implements the corresponding signet.Store method.
func (s *Store) ConsumeToken(ctx context.Context, kind signet.TokenKind, hash string) (*signet.Token, error) {
	return scanToken(s.pool.QueryRow(ctx,
		"UPDATE signet_tokens SET used_at = NOW() WHERE kind = $1 AND hash = $2 AND used_at IS NULL RETURNING id, user_id, kind, hash, expires_at, used_at, created_at",
		string(kind), hash))
}

// TokenByHash implements the corresponding signet.Store method.
func (s *Store) TokenByHash(ctx context.Context, kind signet.TokenKind, hash string) (*signet.Token, error) {
	return scanToken(s.pool.QueryRow(ctx,
		"SELECT id, user_id, kind, hash, expires_at, used_at, created_at FROM signet_tokens WHERE kind = $1 AND hash = $2", string(kind), hash))
}

// DeleteTokensForUser implements the corresponding signet.Store method.
func (s *Store) DeleteTokensForUser(ctx context.Context, userID string, kind signet.TokenKind) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM signet_tokens WHERE user_id = $1 AND kind = $2", userID, string(kind))
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*signet.User, error) {
	var user signet.User
	err := row.Scan(&user.ID, &user.Email, &user.EmailVerified, &user.Name, &user.Disabled, &user.CreatedAt, &user.UpdatedAt)
	return &user, mapNoRows(err)
}

func scanAccount(row rowScanner) (*signet.Account, error) {
	var account signet.Account
	var provider string
	err := row.Scan(&account.ID, &account.UserID, &provider, &account.ProviderUserID,
		&account.Email, &account.EmailVerified, &account.PasswordHash, &account.CreatedAt)
	account.Provider = provider
	return &account, mapNoRows(err)
}

func scanSession(row rowScanner) (*signet.Session, error) {
	var session signet.Session
	err := row.Scan(&session.ID, &session.UserID, &session.TokenHash, &session.CreatedAt,
		&session.LastSeenAt, &session.IdleExpiresAt, &session.AbsoluteExpiresAt, &session.RevokedAt)
	return &session, mapNoRows(err)
}

func scanToken(row rowScanner) (*signet.Token, error) {
	var token signet.Token
	var kind string
	err := row.Scan(&token.ID, &token.UserID, &kind, &token.Hash, &token.ExpiresAt, &token.UsedAt, &token.CreatedAt)
	token.Kind = signet.TokenKind(kind)
	return &token, mapNoRows(err)
}

func mapNoRows(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return signet.ErrNotFound
	}
	return err
}

func requireRows(rows int64, err error) error {
	if err != nil {
		return err
	}
	if rows == 0 {
		return signet.ErrNotFound
	}
	return nil
}
