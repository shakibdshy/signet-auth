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

## Documentation

Documentation will live in [`docs/`](docs/) as the project takes shape. Runnable
examples for several routers are planned under [`examples/`](examples/).

## License

[MIT](LICENSE)
