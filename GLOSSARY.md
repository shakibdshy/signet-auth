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

**Session cache**:
An optional, short-lived copy of a Session used to answer a lookup without a Store read.
_Avoid_: session store, cached session

**Secondary store**:
A Store backed by a system other than the application's primary database.
_Avoid_: secondary storage, cache store

**Revocation lag**:
The time between a Session being revoked and every cache reflecting that revocation.
_Avoid_: staleness window

**Key ring**:
An ordered set of signing keys in which the first signs and every key can verify.
_Avoid_: key list, key set

**Redirect pattern**:
A configured pattern that matches a set of redirect destinations, used where an exact allowlist is insufficient.
_Avoid_: wildcard origin, origin pattern

**Token**:
A single-use proof for one sensitive flow: email verification, email change, password reset, email change confirmation, account deletion, OAuth account linking, refresh, state, email OTP sign-in or magic-link sign-in. Only its digest is stored.
_Avoid_: verification value, one-time secret

**Email OTP**:
A six-digit one-time code delivered to a User's email as a single-use proof of that address.
_Avoid_: passcode, verification code

**Magic link**:
A URL carrying a single-use Token that signs a User in when opened.
_Avoid_: login link, sign-in link

**Username**:
A human-chosen identifier for a User, represented as an Account whose name is the identifier.
_Avoid_: handle, login name

**Second factor**:
An additional proof required after a first factor before a Session is created.
_Avoid_: 2FA, two-step verification

**TOTP code**:
A time-based one-time code derived from a shared secret and the current time.
_Avoid_: authenticator code, OTP

**Backup code**:
A single-use fallback proof issued when a Second factor is enabled.
_Avoid_: recovery code, backup passcode

**Two-factor challenge**:
A short-lived, single-use proof issued after a valid first factor and exchanged for a Session together with a Second factor.
_Avoid_: 2FA token, challenge token

**Breach check**:
A check that a proposed password has not appeared in a known password breach.
_Avoid_: HIBP check, password screening

**Captcha check**:
A check that a request came from a person rather than an automated client.
_Avoid_: bot check, challenge

**Audit event**:
A structured record of a security-relevant action and its outcome.
_Avoid_: log entry, audit log

**Role**:
A named set of permissions that can be granted to a User or an API key.
_Avoid_: group, privilege level

**Permission**:
An action allowed on a named resource.
_Avoid_: scope, right

**Organization**:
A group of Users that share membership and role assignments.
_Avoid_: tenant, team

**Membership**:
A User's role-bearing association with an Organization.
_Avoid_: member role, org membership

**Active organization**:
The Organization selected for the current authenticated visit.
_Avoid_: current org, selected tenant

**API key**:
A credential issued to a non-human client and presented instead of a User Session. It is not an Account.
_Avoid_: token, service account

**Impersonation**:
A temporary Session created by an administrator acting as another User.
_Avoid_: sudo, act-as

**Last sign-in method**:
The method used in a User's most recent successful sign-in.
_Avoid_: last login method

**Access token**:
A short-lived bearer credential presented to an API on each request.
_Avoid_: session token

**Refresh token**:
A long-lived credential used only to obtain a new Access token. It is rotated on every use.
_Avoid_: session token

**OAuth identity**:
A provider's assertion about a User's external identity: a provider user ID, an email and whether that email is verified.
_Avoid_: profile, user info

**Provider discovery**:
The process of fetching a Provider's endpoints and issuer metadata from its published well-known document.
_Avoid_: OIDC discovery, discovery document

**ID token**:
A signed assertion from a Provider about the authenticated User's identity.
_Avoid_: identity token, id_token

**CSRF token**:
A signed value that proves a browser request is same-origin. It is not single-use and is distinct from a Token.
_Avoid_: anti-CSRF value

**Sign-in client**:
The browser or application from which a User signed in to start a Session.
_Avoid_: device

**Fresh session**:
A Session created within the configured freshness window, measured from the moment the User authenticated — not from their most recent request.
_Avoid_: recent session, active session

**Trusted proxy**:
A proxy whose address is explicitly allowlisted for interpreting `X-Forwarded-For` when deriving rate-limit keys.
_Avoid_: forwarding proxy, reverse proxy

**Passkey**:
A discoverable public-key credential a User signs in with instead of a password. It is not an Account and requires no username.
_Avoid_: WebAuthn login, passwordless credential

**WebAuthn credential**:
The stored public-key record backing a Passkey, scoped to one Relying party and one User.
_Avoid_: passkey row, authenticator record

**Relying party**:
The site or application whose identity a Passkey is bound to; WebAuthn checks the Relying party ID on every ceremony.
_Avoid_: RP, relying party ID

**Attestation**:
The authenticator's statement about itself at Passkey registration. Signet does not request attestation by default, protecting User privacy.
_Avoid_: registration proof, device proof

**Assertion**:
The authenticator's signed proof of possession at Passkey sign-in.
_Avoid_: login signature, authentication proof

**Automatic sign-in**:
Issuing a Session as part of a successful Sign-up or email-verification flow, without a separate Sign-in call. It is not a new first factor.
_Avoid_: auto-login, implicit sign-in

**Authorization server**:
The role a Relying party takes when it issues Access tokens and Refresh tokens to OAuth clients. Signet is a relying party by default and becomes an Authorization server only when this capability is enabled.
_Avoid_: OAuth provider, identity provider

**OAuth client**:
A registered application that requests an Authorization grant and receives tokens from the Authorization server.
_Avoid_: client app, consumer

**Authorization grant**:
The proof an OAuth client exchanges for tokens: an authorization code with PKCE, a Refresh token, or a device authorization.
_Avoid_: login code, grant token

**Scope**:
A named permission requested by an OAuth client and carried in an issued token. Scopes are exact strings and are never wildcard-expanded.
_Avoid_: permission scope, role

**Consent**:
The User's approval of an OAuth client's requested Scopes before an Authorization grant is issued.
_Avoid_: permission screen, approval token

**Device authorization**:
A flow in which a device with no browser asks for a User code, the User approves it in a browser, and the device polls for tokens.
_Avoid_: device login, TV flow

**User code**:
The short, human-readable code a User enters during Device authorization.
_Avoid_: device code, pairing code

**SSO connection**:
An Organization's configuration for an external identity provider used to sign in its Users.
_Avoid_: IdP config, provider connection

**Subject**:
The stable identifier an external identity provider assigns to a User.
_Avoid_: external ID, provider user ID

**Just-in-time provisioning**:
Creating a User on the first successful sign-in through an SSO connection, using the verified claims from that assertion.
_Avoid_: auto-create, lazy registration

**Service provider**:
The role Signet takes in SAML when it consumes an Identity provider's assertion to sign in a User.
_Avoid_: SP, relying party

**SAML assertion**:
A signed statement from an Identity provider that authenticates a User and carries attributes about them.
_Avoid_: SAML response, login token

**Assertion consumer service**:
The endpoint that receives a SAML assertion from an Identity provider and completes the sign-in ceremony.
_Avoid_: ACS callback, SAML callback

**NameID**:
The subject identifier an Identity provider places in a SAML assertion.
_Avoid_: SAML subject, name identifier

**SCIM**:
A protocol for provisioning Users and Groups between a directory and an application. It does not authenticate Users.
_Avoid_: directory sync, identity provisioning

**Directory group**:
A Group in an external directory whose members are projected to application roles or Organization memberships.
_Avoid_: SCIM group, external group

**Rate-limit window**:
A bounded interval over which requests are counted for a rate-limit rule. A sliding window moves with each request; a fixed window resets at a boundary.
_Avoid_: rate-limit period, quota interval

**Audit query**:
A filtered read of recorded Audit events. Querying is separate from emitting an event and is an application-owned capability.
_Avoid_: audit log search, event lookup
