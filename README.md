# Signet

A modern, secure-by-default, embeddable authentication library for Go.

> **Status:** v0.1.0 — the Version 1 feature set is complete. The API may still
> change before 1.0. Evaluate carefully before production use.

Signet is a library imported into your application, not a separate auth server.
It is built on `net/http` primitives, so it works with the standard library or
any router, and it never owns your database schema.

## Features

- Email/password authentication with Argon2id, transparent rehash and a bcrypt option
- Cookie sessions with idle and absolute timeouts, plus optional JWT access and refresh tokens
- OAuth sign-in with Google and GitHub, PKCE and verified-only account linking
- Email verification and password reset with single-use, hashed tokens
- Same-origin checks and signed double-submit CSRF protection
- PostgreSQL and SQLite adapters with explicit, embedded migrations
- Pluggable storage, mail, password hashing, rate limiting and logging
- Structured events with `slog` and redacted application hooks

## Design principles

- **Secure by default.** Safe choices are the default; insecure behaviour must be opted into explicitly.
- **Router-agnostic (`net/http`).** Signet speaks standard `http.Handler` and `http.Request`, not a framework API.
- **Bring your own schema.** You own and migrate your database tables. Signet adapts to them rather than taking over your data model.
- **Pluggable everything.** Storage, mail delivery, password hashing, rate limiting and OAuth providers are interfaces with swappable implementations.
- **Small API.** A focused surface that is easy to learn, review and audit.
- **Great docs.** Clear, example-driven documentation is part of the product.

## Five-minute quickstart

Install the module and create a client with a store, mailer, rate limiter and CSRF key:

```go
package main

import (
	"context"
	"crypto/rand"
	"log"
	"os"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/mailer/console"
)

func main() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	cfg := signet.DefaultConfig()
	cfg.Store = myStore            // implements signet.Store
	cfg.Mailer = console.New(os.Stdout) // development only
	cfg.RateLimiter = myLimiter    // implements signet.RateLimiter
	cfg.CSRFKey = key
	cfg.AppURL = "https://app.example.com"
	auth, err := signet.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	_, err = auth.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse battery staple",
	})
	if err != nil {
		log.Fatal(err)
	}
	result, err := auth.SignIn(context.Background(), signet.SignInInput{
		Email: "user@example.com", Password: "correct horse battery staple",
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = result.SessionToken
}
```

Mount `auth.Handler()` on any router to expose `/signup`, `/signin`, `/signout`,
`/sessions`, `/session`, `/token`, `/csrf-token` and the verification, reset and
OAuth endpoints. Runnable apps for four routers live in [`examples/`](examples/).

## Security

- Passwords use Argon2id with OWASP-recommended parameters; verifiers carry their algorithm and parameters and are rehashed transparently on sign-in.
- Sessions use 32-byte opaque tokens; only their SHA-256 digest is stored. Cookies are `HttpOnly`, `Secure` and `SameSite=Lax`, with a `__Host-` prefix where valid.
- State-changing requests carrying a session cookie are checked against `Origin` and `Sec-Fetch-Site` and require a signed double-submit CSRF token in `X-CSRF-Token`. This applies to headerless clients too when they use cookies; use JWT mode for non-browser clients. Obtain the token from `GET /csrf-token` or the sign-in response.
- Verification, reset and refresh tokens are random, single-use, short-lived and stored only as digests; unknown-email responses do not disclose account existence.
- OAuth uses PKCE with an encrypted, expiring state and an allowlisted redirect target. Only verified emails are auto-linked.
- Rate limiting applies to sign-up, sign-in, reset and verification endpoints. Nothing logs passwords, tokens or secrets.

Only disable protections with the explicitly named `Insecure*` options, which emit warnings. See [`SECURITY.md`](SECURITY.md) for reporting vulnerabilities.

## Sessions and cookies

Wrap handlers with `auth.RequireAuth` (or `auth.OptionalAuth` for public pages)
and read the User with `signet.UserFromContext(r.Context())`. Idle and absolute
timeouts are enforced on every request; expired Sessions are revoked. List and
revoke Sessions with `ListSessions`, `RevokeSession` and `RevokeAllSessions`, or
the matching HTTP endpoints. Listing never returns a token digest.

## Optional JWT mode

Set `Config.JWT` to issue short-lived Access tokens and rotating Refresh tokens
for API clients. An explicit key and algorithm are required; only `HS256`,
`RS256` and `EdDSA` are accepted. `POST /token` exchanges credentials or a
Refresh token, and replay of a consumed Refresh token revokes all Sessions and
Refresh tokens for that User. Set `Config.JWTOnly` for API-only applications: no
session cookies are issued and no CSRF key is required.

## Email verification and password reset

By default, sign-up sends a verification email and sign-in requires a verified
email. Tokens are short-lived, single-use and stored only as digests; a reset
revokes every Session. Templates are rendered by the `EmailTemplates` interface,
with HTML and plain-text defaults. `mailer/smtp` uses STARTTLS by default;
`mailer/console` is for development only. Point `SendVerificationOnSignUp` or
`RequireVerifiedEmail` at `false` if your product does not use email verification.

## OAuth sign-in

Register providers through `Config.OAuth` with a 32-byte `StateKey`, an
application origin and an exact redirect allowlist. `POST /oauth/start` returns
the authorization URL; `GET /oauth/callback` redeems the code and redirects.
`oauth/google` and `oauth/github` are built in, and the root `OAuthProvider`
interface lets you add more without changing the core.

## Storage

`store/postgres` and `store/sqlite` accept a pool or database you own.
Migrations are explicit and idempotent; Signet never migrates automatically.
For an existing users table, implement the four narrow Store contracts
yourself — see [`docs/custom-schema.md`](docs/custom-schema.md). Any Store can
be validated with the shared suite in `store/conformance`.

## Comparison

| | Signet | Goth | Authboss | Ory Kratos |
| --- | --- | --- | --- | --- |
| Form | Embedded Go library | Embedded Go library | Embedded Go library | Standalone identity service |
| Password auth | Yes | No | Yes | Yes |
| Sessions / JWT | Both | Neither | Server-side sessions | Sessions + tokens |
| OAuth | Google, GitHub | Many providers | Limited | Configurable |
| Schema ownership | Yours or bundled SQL | N/A | More opinionated | Service-owned |
| Router coupling | `net/http` only | `net/http` | Framework-friendly | HTTP API |

Goth focuses on social OAuth only. Authboss is more opinionated about storage
and application structure. Kratos is a separate server you run and call over an
API. Signet aims to sit in between: an embeddable library with a small API and
no schema ownership.

## Limitations

Sign-up writes the User and its credential Account in two store calls; if the
second fails, Signet deletes the new User on a best-effort basis. There is no
transaction across Store calls. Passkeys, TOTP, magic links and organizations
are planned for later versions.

## Documentation

The domain vocabulary lives in [`GLOSSARY.md`](GLOSSARY.md) and architectural
decisions in [`docs/adr/`](docs/adr/). Runnable examples are in [`examples/`](examples/).

## License

[MIT](LICENSE)
