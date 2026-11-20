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

Mount `auth.Handler()` on any router to expose `/signup`, `/signin`, `/signout`,
`/sessions`, `/session` and `/token` as JSON endpoints. Storage adapters ship in
a later phase; until then, bring your own `Store` implementation.

## Sessions and cookies

The HTTP sign-in endpoint sets a `HttpOnly`, `Secure`, `SameSite=Lax` cookie
containing the raw Session token; the store keeps only its digest. The cookie
uses a `__Host-` prefix when Secure, scoped to `/`, with no Domain. Wrap your
handlers with `auth.RequireAuth` (or `auth.OptionalAuth` for public pages) and
read the User with `signet.UserFromContext(r.Context())`. Idle and absolute
timeouts are enforced on every request; expired Sessions are revoked.

State-changing requests carrying the session cookie are same-origin checked via
`Origin` and `Sec-Fetch-Site`; a failed check returns `403`. Browser clients
that send neither header are allowed so non-browser clients keep working. Only
disable this with `InsecureDisableCSRF` when another layer provides equivalent
protection.

List and revoke Sessions with `ListSessions`, `RevokeSession` and
`RevokeAllSessions`, or the matching HTTP endpoints. Listing never returns a
token digest.

```go
mux := http.NewServeMux()
mux.Handle("/auth/", auth.Handler())
mux.Handle("/private", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user, ok := signet.UserFromContext(r.Context())
	if !ok {
		return
	}
	fmt.Fprintln(w, user.Email)
})))
```

## Optional JWT mode

Set `Config.JWT` to issue short-lived Access tokens and rotating Refresh
tokens for API clients. An explicit signing key and algorithm are required;
only `HS256`, `RS256` and `EdDSA` are accepted. `POST /token` exchanges
credentials or a Refresh token. A replayed Refresh token revokes all Sessions
and Refresh tokens for that User.

```go
cfg.JWT = &signet.JWTConfig{
	Algorithm: "HS256",
	Key:       signingKey, // []byte for HS256, *rsa.PrivateKey for RS256, ed25519.PrivateKey for EdDSA
}
```

## Email verification and password reset

By default, sign-up sends a verification email and sign-in requires a verified
email. Configure the application origin used in links and choose a mailer:

```go
cfg := signet.DefaultConfig()
cfg.AppURL = "https://app.example.com"
cfg.Mailer = smtpMailer // from mailer/smtp, or console.New(os.Stdout) for development
```

`SendVerification` / `VerifyEmail` and `SendPasswordReset` / `ResetPassword`
are available as Go methods and as JSON endpoints at `/send-verification`,
`/verify-email`, `/send-password-reset` and `/reset-password`. Tokens are
short-lived, single-use and stored only as digests; reset requests never reveal
whether an email is registered, and a successful reset revokes every Session.
Both flags default to true; point `SendVerificationOnSignUp` or
`RequireVerifiedEmail` at `false` if your product does not use email
verification.

Email content is rendered through the `EmailTemplates` interface. The default
implementation ships HTML and plain-text templates; set `Config.Templates` to
replace them. The `mailer/console` adapter writes messages to an `io.Writer`
and is for development only because it prints links. The `mailer/smtp` adapter
uses STARTTLS by default, supports implicit TLS and requires an explicit switch
for plaintext transport.

## Current state

Phase 3 is in place: email verification, password reset, email templates and
mailer adapters. OAuth and database adapters arrive in later phases.

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
