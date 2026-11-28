# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The generated OpenAPI and TypeScript schema for the organization-member and
  admin request bodies now match what the handlers actually decode. The
  member endpoints advertise `organization_id` (the handler never accepted the
  documented `org_id`), and `admin-users/role`, `admin-users/ban`,
  `admin-users/unban`, `admin-user-sessions/revoke` and `impersonate` advertise
  the snake_case `user_id`, `roles`, `reason` and `session_id` keys the handlers
  decode, instead of the Go-cased keys a schema without tags produced.
  Handlers and the wire are unchanged — only the generated contract and the
  typed client schema moved to describe it truthfully.

## [1.0.0-beta.3] - 2026-11-28

### Added

- `POST /auth/organization-members/add` accepts `email` as an alternative to
  `user_id`, resolving an existing User through the application Store with the
  same normalization as sign-up. Exactly one identifier is required; both or
  neither return `400 invalid_input`, and an unknown email returns `404
  user_not_found`. No invitation email is sent — someone without an account
  must sign up first.
- Guarded organization and admin endpoints now answer a resolvable but stale
  Session (older than `Accounts.FreshWindow`) with `403 session_not_fresh`
  instead of the generic `403 forbidden`, so clients can re-authenticate and
  retry rather than mistaking the freshness window for a role denial. This
  also gives `ErrSessionNotFresh` a wire mapping at all: the account and
  two-factor endpoints that return it answered `500 internal_error` before.
  A missing `organization_id` returns `400 invalid_input` (sentinel
  `signet.ErrMissingOrgID`) instead of the generic `403 forbidden` a wrong id
  used to produce.
- A built-in organization policy is installed when `OrganizationStore` is set
  and `AuthorizeIn` is not: `organizations:member-add`, `member-remove` and
  `member-role` go to the organization's `owner` and `admin` members, with
  membership re-read on every check (`signet.NewOrgAuthorizeIn` returns the
  same policy for explicit wiring). Previously the fallback was the global
  `Authorizer`, whose seam has no organization context and could never see
  org roles.

### Changed

- **Breaking (wire key casing):** `POST /passkeys/signin-finish` now returns
  `user` and `session_token` (were `User` and `SessionToken`), and
  `GET /admin-user-sessions` now returns `sessions` (was `Sessions`) — the same
  snake_case keys every other endpoint uses. Clients reading the Go-cased keys
  must switch to the lowercase forms.

## [1.0.0-beta.2] - 2026-11-27

### Added

- Sessions record the sign-in client: the `User-Agent` header of the request
  that created a Session is stored on the Session (truncated to 512
  characters, empty when absent) and returned as `user_agent` by
  `GET /sessions`. Bundled adapters gain a replay-safe `0002` migration; run
  `Migrate` again on upgrade.
- `GET /me` returns the full profile: `email_verified`, `username` (empty
  when the User has none), `created_at` and `updated_at` alongside the
  existing fields.
- Every session-establishing response carries `last_sign_in_method`:
  `POST /signin`, `POST /verify-two-factor`, `POST /verify-otp`,
  `GET /verify-magic-link`, `POST /signup` and `POST /verify-email` (exactly
  when `session_token` is present), `POST /passkeys/signin-finish`,
  `GET /sso/callback`, `POST /saml/acs` and `POST /token`. The stdlib example
  enables the Last sign-in method cookie.
- Credential sign-in responses (`POST /signin`, `POST /verify-two-factor`,
  `POST /token`) carry `last_sign_in_method` in the body, independent of the
  optional Last sign-in method cookie.

### Changed

- Sign-in method values are canonical, defined once and documented as
  exactly: `password`, `magic_link`, `otp`, `passkey`, `oauth`, `sso`,
  `saml`. A Username credential now reports `password` (was `username`);
  magic-link sign-in reports `magic_link` (was `magic-link`); Email OTP
  reports `otp` (was `email-otp`); OAuth sign-in reports `oauth` (was the
  provider name); automatic sign-in after sign-up reports `password` and
  after email verification `magic_link` (was `email`).
- The Two-factor challenge response no longer writes the Last sign-in method
  cookie; it is written when the second factor completes and a Session is
  created.

## [1.0.0-beta] - 2026-11-25

The first public release of Signet: a secure-by-default, embeddable
authentication library for Go. Signet is imported into your application, not
deployed beside it. It is built on `net/http`, works with any router, and never
owns your database schema. The Go module ships together with the first
publication of the typed TypeScript and React clients.

- Go: `go get github.com/shakibdshy/signet-auth@v1.0.0-beta`
- npm: [`@shakibdshy/signet-auth-client`](https://www.npmjs.com/package/@shakibdshy/signet-auth-client)
  and [`@shakibdshy/signet-auth-react`](https://www.npmjs.com/package/@shakibdshy/signet-auth-react)
  at `1.0.0-beta`; installing the React package installs the typed client
  automatically.

### Added

#### Authentication

- Email/password auth with Argon2id hashing, transparent rehash and an optional
  bcrypt adapter.
- Passwordless first factors: magic links, email OTP and usernames.
- Passkeys (WebAuthn) as a first factor, with an application-owned credential
  store and single-use ceremony proofs.
- TOTP second factor with backup codes.
- OAuth sign-in with Google, GitHub and generic OIDC: PKCE with encrypted
  expiring state, a redirect allowlist and verified-only account linking.
- Automatic sign-in after sign-up or verification, with a combined
  verify-and-sign-in method.
- Email verification, verified email change, password reset and verified
  account deletion, all via single-use hashed proofs.

#### Sessions, tokens and request security

- Cookie sessions with idle and absolute timeouts, auth middleware, session
  listing and revocation.
- Optional JWT access tokens with rotating hashed refresh tokens, replay
  containment, key rings and JWKS.
- Signed double-submit CSRF with same-origin checks.
- Trusted proxies, a window-aware rate limiter, breach checks and captcha
  checks.

#### Authorization

- Application-managed roles and permissions.
- Digest-only API keys with atomic verification and an opt-in per-route
  middleware.
- Organizations with memberships and an active-organization cookie.
- Guarded admin management with impersonation: fresh-session confirmation,
  queryable audits and self-action blocks.
- Account controls: `UpdateUser`, `SetPassword`, `VerifyPassword`.

#### Federation and provisioning (opt-in)

- Authorization server: authorization code with PKCE, refresh token rotation,
  exact scopes, audiences, consent callback and device authorization.
- Per-organization OIDC SSO and SAML 2.0 web SSO.
- SCIM 2.0 user and group provisioning with group-to-role projection.

#### TypeScript and React clients

- The typed client covers every frontend-reachable endpoint of the HTTP
  contract: second factor management (`enableTwoFactor`, `verifyTwoFactor`,
  `disableTwoFactor`, `regenerateBackupCodes`), verified email change
  (`changeEmail`, `verifyChangeEmail`), linked account listing and unlinking
  (`listAccounts`, `unlinkAccount`) and account deletion
  (`requestAccountDeletion`, `confirmAccountDeletion`).
- React package with `SignetProvider`, `useSession()` and `sessionGuard`.
- Framework-neutral `GET /me` endpoint for non-React frontends.

#### Storage, tooling and examples

- Bring-your-own-schema storage with PostgreSQL and SQLite adapters and
  explicit migrations.
- Optional `signet.DocsHandler()` serving the generated OpenAPI document and a
  Scalar reference page.
- Examples for the standard library, chi, echo, gin and Fiber, backed by the
  PostgreSQL adapter against a local database configured with
  `SIGNET_DATABASE_URL`.
- Fuzz targets for Argon2 verifier parsing, session tokens, JSON request
  bodies, OAuth state and CSRF tokens, with a `make fuzz` target.

> **Status:** pre-1.0 beta. The planned feature set is implemented; the
> API-stability commitment arrives with `v1.0.0`.

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
  and bcrypt. Other dependencies appear in later phases.
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
- Original Phase 5 (pre-message-numbering) storage: PostgreSQL and SQLite Store adapters with embedded explicit
  migrations, a public shared Store conformance suite, a custom-schema guide,
  and ADR 0003.
- Original Phase 6 (pre-message-numbering) release hardening: signed double-submit CSRF tokens, four runnable
  router examples in separate modules, a rewritten README with a five-minute
  quickstart and comparison, ADR 0004, and the v0.1.0 tag.
