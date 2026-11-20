package signet

import "time"

// User is the person whose identity Signet manages. A User is the stable
// subject that Accounts and Sessions belong to.
type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Name          string    `json:"name"`
	Disabled      bool      `json:"disabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Account is a named way a User authenticates: either a credential or a link
// to an external identity provider. A User has one credential Account and may
// have several provider Accounts.
type Account struct {
	ID     string
	UserID string
	// Provider is "credential" for the Account holding a password verifier,
	// or the name of an external provider for a linked Account.
	Provider       string
	ProviderUserID string
	Email          string
	EmailVerified  bool
	// PasswordHash is the encoded verifier. It is populated only on the
	// credential Account; provider Accounts leave it empty.
	PasswordHash string
	CreatedAt    time.Time
}
