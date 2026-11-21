# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Optional `signet.DocsHandler()` serves the generated OpenAPI document and a
  Scalar reference page. Mount it deliberately; the authentication handler is
  unchanged.

### Changed

- Reorganized the repository into real folders. The root `signet` package is now
  a façade over private modules in `internal/` (`core`, `auth`, `session`,
  `token`, `oauth`, `csrf`, `mail`, `secret`, `httpapi`). The public import path
  and every exported name are unchanged.
- Examples now use the PostgreSQL adapter against a local Docker/OrbStack
  database, configurable with `SIGNET_DATABASE_URL`.
- Added a Fiber example module that bridges Signet's `net/http` handlers and
  middleware with Fiber's `middleware/adaptor`.
- Added fuzz targets for Argon2 verifier parsing, Session tokens, JSON request
  bodies, OAuth state and CSRF tokens, with a `make fuzz` target and a bounded
  CI run.
- Refactored CSRF into one private module: signing, validation, cookie policy,
  same-origin checks and exemptions now sit behind a single internal seam.
  No public interface changed.

## [0.1.0] - 2026-11-20

### Added

- Initial project structure, documentation, tooling, and CI configuration.
- Phase 0 foundation: root-package configuration with secure defaults,
  composed Store, Mailer, PasswordHasher, RateLimiter and Clock contracts,
  default User, Account, Session and Token model, sentinel errors, and a
  router-agnostic HTTP surface with placeholder endpoints.
- Domain glossary and decision records for the Go version floor and the
  root-package API boundary.
- Phase 1 email and password authentication: programmatic and HTTP sign-up,
  sign-in and sign-out, Argon2id verifiers with OWASP parameters, a bcrypt
  adapter, transparent rehash, anti-enumeration timing, rate limiting,
  Sessions with hashed tokens, redacted hooks and structured events.
  `golang.org/x/crypto` is the only third-party dependency, used for Argon2id
  and bcrypt.
- Phase 2 session and token support: secure session cookies with derived
  __Host- prefix, RequireAuth and OptionalAuth with idle and absolute timeout
  enforcement, a same-origin CSRF guard, session listing and revocation,
  optional JWT mode with rotating hashed Refresh tokens and replay containment,
  and the /token endpoint.
- Phase 3 verification and reset: email templates with HTML and plain-text
  defaults, console and SMTP mailer adapters, single-use hashed verification
  and reset Tokens, anti-enumeration, the verified-email sign-in gate, session
  revocation and password-changed notifications.
- Phase 4 OAuth sign-in: root OAuthProvider contract, Google and GitHub
  adapters, PKCE with encrypted expiring state, redirect allowlist,
  verified-only auto-linking, one-time explicit link tokens and session
  creation on callback.
- Phase 5 storage: PostgreSQL and SQLite Store adapters with embedded explicit
  migrations, a public shared Store conformance suite, a custom-schema guide,
  and ADR 0003.
- Phase 6 release hardening: signed double-submit CSRF tokens, four runnable
  router examples in separate modules, a rewritten README with a five-minute
  quickstart and comparison, ADR 0004, and the v0.1.0 tag.
