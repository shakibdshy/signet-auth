# Signet

A modern, secure-by-default, embeddable authentication library for Go. This glossary defines the domain language used across Signet's code, docs and issues.

## Language

**User**:
The person whose identity Signet manages. A User is the stable subject that Accounts and Sessions belong to.
_Avoid_: account, member, principal

**Account**:
A named way a User authenticates: either a credential or a link to an external identity provider. A User has at most one credential Account and may have several provider Accounts.
_Avoid_: provider, login method, identity

**Credential account**:
The Account that holds a User's password verifier. It is created when the User sets a password; a User who signs in only with a proof has no credential Account.
_Avoid_: password record, user password

**Session**:
One authenticated visit by a User, with its own idle and absolute lifetimes.
_Avoid_: login, cookie

**Session token**:
The raw value a Session presents when authenticating. It is stored only as a digest and is distinct from a Token.
_Avoid_: bearer token, session secret

**Token**:
A single-use proof for one sensitive flow: email verification, email change, password reset, email change confirmation, account deletion, OAuth account linking, refresh, state, email OTP sign-in or magic-link sign-in. Only its digest is stored.
_Avoid_: proof, verification value

**Email OTP**:
A six-digit one-time code delivered to a User's email as a single-use proof of that address.
_Avoid_: passcode, verification code

**Magic link**:
A URL carrying a single-use Token that signs a User in when opened.
_Avoid_: login link, sign-in link

**Access token**:
A short-lived bearer credential presented to an API on each request.
_Avoid_: session token

**Refresh token**:
A long-lived credential used only to obtain a new Access token. It is rotated on every use.
_Avoid_: session token

**OAuth identity**:
A provider's assertion about a User's external identity: a provider user ID, an email and whether that email is verified.
_Avoid_: profile, user info

**CSRF token**:
A signed value that proves a browser request is same-origin. It is not single-use and is distinct from a Token.
_Avoid_: anti-CSRF value

**Fresh session**:
A Session created within the configured freshness window, measured from the moment the User authenticated — not from their most recent request.
_Avoid_: recent session, active session

**Trusted proxy**:
A proxy whose address is explicitly allowlisted for interpreting `X-Forwarded-For` when deriving rate-limit keys.
_Avoid_: forwarding proxy, reverse proxy
