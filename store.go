package signet

import (
	"context"
	"time"
)

// Store is the complete persistence contract Signet requires. It composes the
// four narrow contracts so an adapter can be written and tested one concern
// at a time. Lookup misses return ErrNotFound.
type Store interface {
	UserStore
	AccountStore
	SessionStore
	TokenStore
}

// UserStore persists Users.
type UserStore interface {
	// CreateUser persists a new User. The core generates the ID before this
	// call; the store may override it through the pointer it receives.
	CreateUser(context.Context, *User) error
	// UserByID returns the User with the given ID.
	UserByID(context.Context, string) (*User, error)
	// UserByEmail returns the User with the given email address.
	UserByEmail(context.Context, string) (*User, error)
	// UpdateUser persists changes to an existing User.
	UpdateUser(context.Context, *User) error
	// DeleteUser removes the User with the given ID.
	DeleteUser(context.Context, string) error
}

// AccountStore persists Accounts.
type AccountStore interface {
	// CreateAccount persists a new Account. The core generates the ID before
	// this call; the store may override it.
	CreateAccount(context.Context, *Account) error
	// AccountsForUser returns all Accounts owned by a User.
	AccountsForUser(context.Context, string) ([]*Account, error)
	// AccountByProvider returns an Account for a provider and its user ID.
	AccountByProvider(context.Context, string, string) (*Account, error)
	// DeleteAccount removes the Account with the given ID.
	DeleteAccount(context.Context, string) error
}

// SessionStore persists Sessions.
type SessionStore interface {
	// CreateSession persists a new Session. The core generates the ID before
	// this call; the store may override it.
	CreateSession(context.Context, *Session) error
	// SessionByHash returns the Session for a stored token hash.
	SessionByHash(context.Context, string) (*Session, error)
	// TouchSession updates the idle expiry of a Session.
	TouchSession(context.Context, string, time.Time) error
	// DeleteSession revokes a single Session.
	DeleteSession(context.Context, string) error
	// DeleteSessionsForUser revokes every Session owned by a User.
	DeleteSessionsForUser(context.Context, string) error
	// ListSessionsForUser returns every Session owned by a User.
	ListSessionsForUser(context.Context, string) ([]*Session, error)
}

// TokenStore persists Tokens.
type TokenStore interface {
	// CreateToken persists a new Token. The core generates the ID before this
	// call; the store may override it.
	CreateToken(context.Context, *Token) error
	// ConsumeToken atomically claims and returns an unused Token of the given
	// kind. A second call for the same proof must fail.
	ConsumeToken(context.Context, TokenKind, string) (*Token, error)
	// DeleteTokensForUser removes every Token of a kind owned by a User.
	DeleteTokensForUser(context.Context, string, TokenKind) error
}
