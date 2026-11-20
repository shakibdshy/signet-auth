package signet

import "github.com/shakibdshy/signet/internal/core"

// Store is the complete persistence contract Signet requires. It composes the
// four narrow contracts so an adapter can be written and tested one concern
// at a time. Lookup misses return ErrNotFound.
type Store = core.Store

// UserStore persists Users.
type UserStore = core.UserStore

// AccountStore persists Accounts.
type AccountStore = core.AccountStore

// SessionStore persists Sessions.
type SessionStore = core.SessionStore

// TokenStore persists Tokens.
type TokenStore = core.TokenStore
