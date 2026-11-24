# Signet

[![Go Reference](https://pkg.go.dev/badge/github.com/shakibdshy/signet.svg)](https://pkg.go.dev/github.com/shakibdshy/signet)
[![CI](https://github.com/shakibdshy/signet/actions/workflows/ci.yml/badge.svg)](https://github.com/shakibdshy/signet/actions/workflows/ci.yml)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A secure-by-default, embeddable authentication library for Go.

> **Status:** pre-1.0. The planned feature set is implemented; release tagging and the
> 1.0 API-stability commitment are still pending. See [status](https://shakibdshy.github.io/signet/docs/status).

Signet is imported into your application — it is not a separate auth server. It is built on
`net/http`, works with any router, and never owns your database schema.

## Features

- Email/password auth with Argon2id, transparent rehash and an optional bcrypt adapter
- Cookie Sessions with idle and absolute timeouts, plus optional JWT Access and Refresh tokens
- OAuth sign-in with Google, GitHub and generic OIDC, PKCE and verified-only account linking
- Verification, email change, password reset and verified account deletion with single-use proofs
- Passwordless first factors: magic links, email OTP, usernames and TOTP Second factor
- **Passkeys** (WebAuthn) and per-organization **OIDC / SAML SSO**
- **SCIM 2.0** User and Group provisioning with group-to-role projection
- Opt-in **Authorization server** with PKCE, rotating tokens and device authorization
- Application-managed authorization: roles, permissions, API keys, organizations and admin management
- Automatic sign-in, account controls, queryable Audit events and optional React session hooks
- Security controls: signed double-submit CSRF, trusted proxies, rate limits, key rings, JWKS,
  breach checks and captcha checks
- Bring-your-own-schema storage with PostgreSQL and SQLite adapters and explicit migrations

## Five-minute quickstart

This is a complete, runnable program using SQLite and a development-only limiter and mailer.
For production, use a shared limiter, a real mailer and your own schema.

```go
package main

import (
    "context"
    "crypto/rand"
    "database/sql"
    "log"
    "net/http"
    "os"
    "sync"

    "github.com/shakibdshy/signet"
    "github.com/shakibdshy/signet/mailer/console"
    "github.com/shakibdshy/signet/store/sqlite"
    _ "modernc.org/sqlite"
)

type memoryLimiter struct {
    mu   sync.Mutex
    hits map[string]int
}

func (l *memoryLimiter) Allow(_ context.Context, key string) (bool, error) {
    l.mu.Lock()
    defer l.mu.Unlock()
    l.hits[key]++
    return l.hits[key] <= 10, nil
}

func main() {
    ctx := context.Background()

    db, err := sql.Open("sqlite", "file:signet.db?_pragma=foreign_keys(1)")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()
    store := sqlite.New(db)
    if err := store.Migrate(ctx); err != nil {
        log.Fatal(err)
    }

    key := make([]byte, 32)
    if _, err := rand.Read(key); err != nil {
        log.Fatal(err)
    }

    cfg := signet.DefaultConfig()
    cfg.Store = store
    cfg.Mailer = console.New(os.Stdout) // prints links; development only
    cfg.RateLimiter = &memoryLimiter{hits: make(map[string]int)}
    cfg.CSRFKey = key
    cfg.AppURL = "http://localhost:8080"
    cfg.PathPrefix = "/auth"

    off := false // development only: skip email verification
    cfg.RequireVerifiedEmail = &off
    cfg.SendVerificationOnSignUp = &off

    auth, err := signet.New(cfg)
    if err != nil {
        log.Fatal(err)
    }

    if _, err := auth.SignUp(ctx, signet.SignUpInput{
        Email: "user@example.com", Password: "correct horse battery staple",
    }); err != nil {
        log.Fatal(err)
    }

    http.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

Run it, then visit `http://localhost:8080/auth/csrf-token`. Runnable examples for the standard
library, Chi, Echo, Gin and Fiber are in [`examples/`](examples/).

## Documentation

Full step-by-step guides, code examples and the generated API reference live in the
[documentation site](docs-site/) — see `docs-site/README.md` to run it locally.

| Start here | Covers |
| --- | --- |
| [Quickstart](https://shakibdshy.github.io/signet/docs/quickstart) | First running app |
| [Sessions](https://shakibdshy.github.io/signet/docs/sessions) | Cookies, freshness, revocation |
| [OAuth and OIDC](https://shakibdshy.github.io/signet/docs/oauth) | Providers and account linking |
| [Authorization](https://shakibdshy.github.io/signet/docs/authorization) | Roles and permissions |
| [Passkeys](https://shakibdshy.github.io/signet/docs/passkeys) | WebAuthn first factor |
| [Authorization server](https://shakibdshy.github.io/signet/docs/authorization-server) | OAuth tokens and device flow |
| [Organization SSO](https://shakibdshy.github.io/signet/docs/organization-sso) · [SAML](https://shakibdshy.github.io/signet/docs/saml) · [SCIM](https://shakibdshy.github.io/signet/docs/scim) | Enterprise identity |
| [Frontend client](https://shakibdshy.github.io/signet/docs/frontend-client) | Typed client and React hooks |
| [HTTP API reference](https://shakibdshy.github.io/signet/docs/openapi) | Every endpoint |

The domain vocabulary lives in [`GLOSSARY.md`](GLOSSARY.md). Runnable examples are in
[`examples/`](examples/). Security reporting is in [`SECURITY.md`](SECURITY.md).

## Design

- **Secure by default.** Safe choices are defaults; insecure behaviour is explicitly opted into.
- **Router-agnostic.** Signet speaks `http.Handler` and `http.Request`, not a framework API.
- **Bring your own schema.** Signet adapts to your tables; it never auto-migrates or owns them.
- **Optional adapters.** Storage, mail, hashing, rate limiting and providers are interfaces.
- **Small public surface.** The root package is a five-file façade over private `internal/` packages.

## Limitations

Sign-up writes the User and credential Account in two Store calls with best-effort cleanup on
failure; there is no transaction across Store calls. There is no plugin system or bundled
dashboard. Phone OTP, anonymous sessions, One Tap, SIWE, one-time tokens, MCP, CIMD and DPoP
are not implemented. i18n and anomaly detection are out of scope.

## Typed clients

`api/signet.openapi.json` is generated from the declarative contract in
`internal/httpapi/contract.go`; `make generate-check` prevents drift. The TypeScript client in
[`client/ts/`](client/ts/) and React hooks in [`client/react/`](client/react/) are **local packages**,
installed from a checkout — they are not published to npm yet. See
[`client/ts/README.md`](client/ts/README.md) and the frontend guide for setup.

## License

[MIT](LICENSE)
