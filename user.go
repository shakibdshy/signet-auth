package signet

import "github.com/shakibdshy/signet/internal/core"

// User is the person whose identity Signet manages. A User is the stable
// subject that Accounts and Sessions belong to.
type User = core.User

// Account is a named way a User authenticates: either a credential or a link
// to an external identity provider. A User has one credential Account and may
// have several provider Accounts.
type Account = core.Account
