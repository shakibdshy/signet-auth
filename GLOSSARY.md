# Signet

A modern, secure-by-default, embeddable authentication library for Go. This glossary defines the domain language used across Signet's code, docs and issues.

## Language

**User**:
The person whose identity Signet manages. A User is the stable subject that Accounts and Sessions belong to.
_Avoid_: account, member, principal

**Account**:
A named way a User authenticates: either a credential or a link to an external identity provider. A User has one credential Account and may have several provider Accounts.
_Avoid_: provider, login method, identity

**Credential account**:
The Account that holds a User's password verifier.
_Avoid_: password record, user password

**Session**:
One authenticated visit by a User, with its own idle and absolute lifetimes.
_Avoid_: login, cookie

**Session token**:
The raw value a Session presents when authenticating. It is stored only as a digest and is distinct from a Token.
_Avoid_: bearer token, session secret

**Token**:
A single-use proof for one sensitive flow: email verification, password reset, or OAuth account linking.
_Avoid_: one-time code

**Access token**:
A short-lived bearer credential presented to an API on each request.
_Avoid_: session token

**Refresh token**:
A long-lived credential used only to obtain a new Access token. It is rotated on every use.
_Avoid_: session token
