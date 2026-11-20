# Signet

A modern, secure-by-default, embeddable authentication library for Go.

> **Status:** early development, not production-ready. The API is unstable and
> may change without notice. Do not use Signet in production yet.

Signet aims to make authentication in Go applications straightforward without
taking control away from the application. It is built on `net/http` primitives,
so it works with the standard library or any router, and it never owns your
database schema.

## Planned features

- Email/password authentication
- Sessions
- OAuth sign-in with Google and GitHub
- Email verification
- Password reset
- PostgreSQL and SQLite storage adapters

## Design principles

- **Secure by default.** Safe choices are the default; insecure behaviour must
  be opted into explicitly.
- **Router-agnostic (`net/http`).** Signet speaks standard `http.Handler` and
  `http.Request`, not a particular framework's API.
- **Bring your own schema.** You own and migrate your database tables. Signet
  adapts to them rather than taking over your data model.
- **Pluggable everything.** Storage, mail delivery, and OAuth providers are
  interfaces with swappable implementations.
- **Small API.** A focused surface that is easy to learn, review, and audit.
- **Great docs.** Clear, example-driven documentation is part of the product.

## Quickstart

Email and password authentication is available from Go and as plain `net/http`
endpoints. Supply implementations of the `Store`, `Mailer` and `RateLimiter`
interfaces; `DefaultConfig()` provides secure defaults for everything else,
including the password hasher.

```go
package main

import (
	"context"
	"log"

	"github.com/shakibdshy/signet"
)

func main() {
	cfg := signet.DefaultConfig()
	cfg.Store = myStore        // implements signet.Store
	cfg.Mailer = myMailer      // implements signet.Mailer
	cfg.RateLimiter = myLimiter // implements signet.RateLimiter

	auth, err := signet.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	_, err = auth.SignUp(context.Background(), signet.SignUpInput{
		Email:    "user@example.com",
		Password: "correct horse battery staple",
	})
	if err != nil {
		log.Fatal(err)
	}

	result, err := auth.SignIn(context.Background(), signet.SignInInput{
		Email:    "user@example.com",
		Password: "correct horse battery staple",
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = result.SessionToken // raw Session token; store only its digest yourself
}
```

Mount `auth.Handler()` on any router to expose `/signup`, `/signin` and
`/signout` as JSON endpoints. Storage adapters ship in a later phase; until
then, bring your own `Store` implementation.

## Current state

Phase 1 is in place: email/password sign-up, sign-in and sign-out work through
both the Go API and the HTTP endpoints, with argon2id verifiers, transparent
rehash, anti-enumeration, rate limiting, Sessions and redacted hooks. Secure
cookies, email verification, OAuth and database adapters arrive in later phases.

### Limitations

Sign-up writes the User and its credential Account in two store calls. If the second fails, Signet deletes the new User on a best-effort basis; true cross-database atomicity arrives with the storage adapters.

### Dependencies

The only third-party dependency is `golang.org/x/crypto`, used for Argon2id and bcrypt. Everything else is the standard library.

## Documentation

The domain vocabulary lives in [`GLOSSARY.md`](GLOSSARY.md) and architectural
decisions in [`docs/adr/`](docs/adr/). Runnable examples for several routers are
planned under [`examples/`](examples/).

## License

[MIT](LICENSE)
