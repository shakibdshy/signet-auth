# Using Signet with an existing users table

The bundled `store/postgres` and `store/sqlite` adapters implement Signet's
default `signet_`-prefixed schema. If your application already owns a users
table, implement the four narrow store contracts yourself instead of renaming
columns in the adapters.

## The four contracts

`signet.Store` composes `UserStore`, `AccountStore`, `SessionStore` and
`TokenStore`, all in the root `signet` package. Implement only the methods your
application needs to support; pass the resulting value as `Config.Store`.

- **UserStore** persists `signet.User`. Signet generates the ID before
  `CreateUser`; your store may overwrite it through the pointer.
- **AccountStore** persists `signet.Account`, including the credential Account
  that holds a password verifier and the provider Accounts created by OAuth.
- **SessionStore** persists `signet.Session`. Lookups are by the SHA-256 digest
  of the raw Session token, never the raw token itself.
- **TokenStore** persists `signet.Token`. `ConsumeToken` must atomically claim a
  single unused Token; a second call must fail. This is the contract that makes
  verification, reset and refresh Tokens single-use.

## Error contract

Lookup misses must return `signet.ErrNotFound` so the core can use `errors.Is`.
Other errors are returned unchanged and mapped to generic HTTP responses.

## Validation

Run the shared suite against your implementation:

```go
conformance.Run(t, func(t *testing.T) signet.Store {
    return newMyStore(t) // fresh, empty store per case
})
```

The suite covers every Store method, not-found behaviour, session revocation,
token replay and concurrent single-use Token consumption. A passing suite is
the bar for a supported adapter.

## Schema ownership

Sessions carry the sign-in client: the `user_agent` column on `signet_sessions`
(raw `User-Agent`, capped at 512 runes). Custom Stores should persist it; the
conformance suite round-trips the field, so an implementation that drops it
fails the suite.

Signet never runs migrations against your database. Apply your own schema
changes through your normal migration tooling. The bundled adapters expose
their SQL as an embedded filesystem and an explicit `Migrate` method for
applications that choose the default schema; neither is required for a custom
Store.
