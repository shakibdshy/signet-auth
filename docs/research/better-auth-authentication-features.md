# Better Auth authentication features, mapped to Signet

**Research date:** 2026-11-21.
**Signet status updated:** 2026-11-22 — foundation, session/token hardening, passwordless sign-in and Phase 3 sign-in/Second factor are shipped. See `docs-site/content/docs/status.mdx` for the authoritative shipped list.
**Source version:** Better Auth **1.7.x**, the current stable line. The root index identifies
1.7 as "Latest" and 1.8 as beta ([version index](https://better-auth.com/llms.txt)); the
documentation index fetched for this note is the [1.7.x index](https://better-auth.com/docs/llms.txt).
All claims below are grounded in the `.md` pages listed in that index, cited by their canonical
URLs without the `.md` suffix.

## How to read this

Better Auth is a TypeScript/framework-oriented authentication *framework*: it owns a schema,
serves an RPC-style HTTP API, ships framework adapters and reactive client hooks, and distributes
most advanced features as npm plugins. Signet is an embeddable Go library built on `net/http`
primitives, with no schema ownership and a deliberately small typed API. The comparison is about
**capability coverage**, not code reuse: a Signet "already" means an equivalent security outcome
is available through a Go API, not that the same endpoint or plugin name exists.

Statuses in the mapping table are deliberately conservative:

- **already** — Signet exposes the capability today through its public API.
- **partial** — some of the capability exists, but not the full Better Auth surface.
- **missing** — no equivalent in Signet's public API.

Sources for Signet's current state: `README.md`, `config.go`, `client.go`, `signet.go`,
`internal/core/core.go`, `internal/httpapi/handler.go`, `docs-site/content/docs/status.mdx`,
and ADRs 0003, 0004, 0005, 0006, 0007, 0008, 0009 and 0010.

---

## 1. Core email/password authentication

- **Enablement and endpoints.** Email/password auth is opt-in (`emailAndPassword.enabled`);
  `POST /sign-up/email`, `POST /sign-in/email`, and `POST /sign-out` are available to both the
  client and `auth.api`; passwords default to 8–128 characters with custom `hash`/`verify`
  functions supported. [Email & Password](https://better-auth.com/docs/authentication/email-password)
- **Password hashing.** The default is `scrypt` (chosen for native Node.js support); Argon2id
  can be supplied through the `password` option, and the [Security reference](https://better-auth.com/docs/reference/security)
  documents the same default and customization.
- **Email verification.** `sendVerificationEmail` is a caller-supplied callback; verification can
  be sent on sign-up (`sendOnSignUp`) and on sign-in (`sendOnSignIn`); `requireEmailVerification`
  gates *password* sign-in only (social sign-in has a separate per-provider gate);
  `autoSignInAfterVerification`, `beforeEmailVerification` and `afterEmailVerification` callbacks
  are supported. [Email](https://better-auth.com/docs/concepts/email) · [Options](https://better-auth.com/docs/reference/options)
- **Email enumeration protection.** When `requireEmailVerification` is true or `autoSignIn` is
  false, sign-up returns the same synthetic `200` for existing and new emails; duplicate sign-ups
  simulate password hashing to blunt timing analysis; `/change-email` also returns success for an
  unknown target. `customSyntheticUser` lets plugins add their fields to the synthetic response.
  [Email & Password](https://better-auth.com/docs/authentication/email-password) · [Security](https://better-auth.com/docs/reference/security)
- **Password reset.** `POST /request-password-reset` and `POST /reset-password`, with
  `sendResetPassword` and `onPasswordReset` callbacks; `revokeSessionsOnPasswordReset` is
  **off by default**; when adapters support transactions, token spend, session revocation and
  password update are atomic, otherwise partial failure modes are documented.
  [Email & Password](https://better-auth.com/docs/authentication/email-password)
- **Change, set and verify password.** `POST /change-password` requires the current password and
  can revoke other sessions; `auth.api.setPassword` is server-only for users without a credential
  account; `auth.api.verifyPassword` confirms identity before sensitive operations.
  [Email & Password](https://better-auth.com/docs/authentication/email-password) · [Users & Accounts](https://better-auth.com/docs/concepts/users-accounts)
- **User profile management.** `updateUser` for name/image; `changeEmail` (opt-in) verifies the
  *new* address, can require confirmation via the *current* address, and offers
  `updateEmailWithoutVerification`; `deleteUser` (opt-in) requires a password, a fresh session, or
  an email-verification link, with `beforeDelete`/`afterDelete` callbacks.
  [Users & Accounts](https://better-auth.com/docs/concepts/users-accounts) · [Options](https://better-auth.com/docs/reference/options)
- **Sign-up auto sign-in.** `emailAndPassword.autoSignIn` controls whether sign-up immediately
  creates a session. [Options](https://better-auth.com/docs/reference/options)
- **Central identity policy gate.** `user.validateUserInfo` rejects an identity at
  create-user/link-account/sign-in for email/password, OAuth, SSO, magic link, email OTP,
  anonymous, SIWE, phone, admin-created users and SCIM, including stateless setups.
  [Users & Accounts](https://better-auth.com/docs/concepts/users-accounts)

## 2. Social OAuth and account linking

- **Built-in providers.** The 1.7 index lists these social providers: Apple, Atlassian,
  Cloudflare, Cognito, Discord, Dropbox, Facebook, Figma, GitHub, GitLab, Railway, Google, Hugging
  Face, Kakao, Kick, LINE, Linear, LinkedIn, Microsoft, Naver, Notion, Paybin, PayPal, Polar,
  Reddit, Roblox, Spotify, Salesforce, Slack, TikTok, Twitch, Twitter/X, Vercel, VK, WeChat and
  Zoom, plus an "Other Social Providers" page. [Documentation index](https://better-auth.com/docs/llms.txt)
- **Sign-in and linking flows.** `signIn.social` / `auth.api.signInSocial`, `linkSocial` /
  `auth.api.linkSocialAccount`, `listAccounts`, ID-token sign-in, incremental scopes through
  re-linking, and pass-through `additionalParams` / `additionalData` with a server-only
  `serverContext` slot for trusted values. [OAuth](https://better-auth.com/docs/concepts/oauth) · [Users & Accounts](https://better-auth.com/docs/concepts/users-accounts)
- **Provider options.** `clientId` may be an array for cross-platform audience verification;
  plus `scope`, `redirectURI`, `prompt`, `responseMode`, `disableSignUp`, `disableImplicitSignUp`,
  `disableDefaultScope`, `requireEmailVerification` (per provider), `mapProfileToUser`,
  `getAccountFields`, `verifyIdToken`, `getUserInfo`, `refreshAccessToken`,
  `overrideUserInfoOnSignIn`. Providers that omit email (Apple, Discord, Facebook, GitHub, Kakao,
  LinkedIn, Microsoft Entra ID, Roblox) have documented stable fallback IDs and placeholder-email
  guidance. [OAuth](https://better-auth.com/docs/concepts/oauth)
- **Account linking policy.** Enabled by default; implicit linking on verified same-email
  sign-in; `trustedProviders` can force linking, `disableImplicitLinking` can require explicit
  consent, `allowDifferentEmails` and `updateUserInfoOnLink` tune linking, and `unlinkAccount`
  uses the local account `id` (with `allowUnlinkingAll` to permit unlinking the last account).
  [Users & Accounts](https://better-auth.com/docs/concepts/users-accounts) · [Options](https://better-auth.com/docs/reference/options)
- **Provider token APIs.** `getAccessToken`, `refreshToken` and `accountInfo` require an explicit
  account selector (`accountId` or `useAccountCookie`); expired access tokens are refreshed
  automatically. `account.encryptOAuthTokens` and `account.storeAccountCookie` cover encrypted
  storage and database-less flows. [OAuth](https://better-auth.com/docs/concepts/oauth) · [Options](https://better-auth.com/docs/reference/options)
- **State, PKCE and outbound safety.** OAuth state/PKCE is stored in verification storage by
  default and additionally persisted in a signed cookie; `storeStateStrategy: "cookie"` encrypts
  the whole payload into a short-lived cookie. Outbound token/refresh/introspection/JWKS requests
  refuse redirects. [Security](https://better-auth.com/docs/reference/security) · [Options](https://better-auth.com/docs/reference/options)

## 3. Sessions, cookies and platform security

- **Session lifecycle.** Database/secondary-storage sessions expire after 7 days and refresh
  when `updateAge` (1 day) is reached; `disableSessionRefresh` and `deferSessionRefresh` cover
  read-replica setups. Session rows record `ipAddress` and `userAgent`.
  [Session Management](https://better-auth.com/docs/concepts/session-management)
- **Freshness.** `session.freshAge` (default 1 day) gates sensitive endpoints; `0` disables the
  check. [Session Management](https://better-auth.com/docs/concepts/session-management)
- **Session APIs.** `getSession`, `useSession`, `listSessions`, `revokeSession`,
  `revokeOtherSessions`, `revokeSessions` (all), `updateSession` (additional fields only), and the
  `customSession` plugin for shaping responses; `disableCookieCache` forces a database read.
  [Session Management](https://better-auth.com/docs/concepts/session-management)
- **Cookie cache.** A separate signed `session_data` cookie with short `maxAge` and three
  strategies: `compact` (base64url + HMAC-SHA256, default), `jwt` (HS256, optionally JWKS-backed
  via the JWT plugin), and `jwe` (A256CBC-HS512 + HKDF). `refreshCache` refreshes before expiry
  without a database; `version` invalidates all caches on redeploy. Revocation may lag until the
  cache expires unless `disableCookieCache` is used for sensitive operations.
  [Session Management](https://better-auth.com/docs/concepts/session-management) · [Cookies](https://better-auth.com/docs/concepts/cookies)
- **Secondary storage.** A pluggable `SecondaryStorage` (`get`, `getAndDelete`, `increment`,
  `set`, `delete`) holds sessions, verification records and rate-limit counters; official Redis
  storage is available. `storeSessionInDatabase` and `preserveSessionInDatabase` control
  database/secondary-storage duality and revoked-row retention.
  [Database](https://better-auth.com/docs/concepts/database) · [Session Management](https://better-auth.com/docs/concepts/session-management)
- **Stateless sessions.** With no database, session, account and state data live in signed/encrypted
  cookies (`jwe`/`jwt`/`compact`, `storeAccountCookie`, `refreshCache`); a version bump invalidates
  them, and they can be combined with Redis. [Session Management](https://better-auth.com/docs/concepts/session-management)
- **Cookies.** Prefix (`better-auth.*` by default), custom names/attributes, `HttpOnly` + `Secure`
  in production, `SameSite=Lax`, `crossSubDomainCookies` with an explicit domain,
  `useSecureCookies`, and reverse-proxy/shared-parent-domain guidance for Safari ITP.
  [Cookies](https://better-auth.com/docs/concepts/cookies) · [Options](https://better-auth.com/docs/reference/options)
- **CSRF.** Non-simple requests are preferred; `Origin` is validated against `trustedOrigins`;
  `SameSite=Lax` is the cookie default; Fetch Metadata (`Sec-Fetch-Site/Mode/Dest`) blocks
  first-login CSRF cross-site navigations; GET mutations (notably OAuth callbacks) use nonce/state.
  `disableCSRFCheck` and `disableOriginCheck` are separate switches (the latter also disables
  CSRF for backward compatibility). Direct `auth.api` calls bypass these checks, so custom routes
  must validate `Origin` themselves. [Security](https://better-auth.com/docs/reference/security)
- **Trusted origins.** Static lists, wildcard patterns (`*.example.com`, `https://*.…`), dynamic
  per-request functions, mobile/extension custom schemes, and validation of `callbackURL`,
  `errorCallbackURL`, `newUserCallbackURL` and `redirectTo`. [Security](https://better-auth.com/docs/reference/security) · [Options](https://better-auth.com/docs/reference/options)
- **Rate limiting.** On by default in production (10s/100), stricter per-path rules such as
  `/sign-in/email` 3/10s and plugin rules such as `/two-factor/*` 3/10s; `customRules`, in-memory /
  database / secondary-storage / custom atomic `consume` storage, and `X-Retry-After` on 429.
  `auth.api` calls are not rate limited. [Rate Limit](https://better-auth.com/docs/concepts/rate-limit) · [Options](https://better-auth.com/docs/reference/options)
- **IP handling.** `X-Forwarded-For` by default; `ipAddressHeaders` for a proxy-set header,
  `trustedProxies` for appended addresses, `disableIpTracking`; IPv6 normalization, IPv4-mapped
  conversion and `/64` subnet limiting to prevent rotation bypasses.
  [Rate Limit](https://better-auth.com/docs/concepts/rate-limit)
- **Secrets and token encryption.** Versioned `secrets` allow non-destructive rotation with direct
  key lookup; legacy fallback is supported within the same encryption purpose. Provider tokens
  are not encrypted by default — `account.encryptOAuthTokens` or `databaseHooks` can encrypt them;
  JWT plugin private keys are AES-256-GCM encrypted by default. Dynamic base URLs can be derived
  from trusted proxy headers. [Security](https://better-auth.com/docs/reference/security) · [Options](https://better-auth.com/docs/reference/options) · [Users & Accounts](https://better-auth.com/docs/concepts/users-accounts) · [JWT plugin](https://better-auth.com/docs/plugins/jwt)
- **Audit/security events.** Automatic audit logging of sign-up, sign-in, session, account,
  verification, organization and security events via the infrastructure dashboard plugin, plus a
  dedicated abuse-detection plugin. [Audit Logs](https://better-auth.com/docs/infrastructure/plugins/audit-logs) · [Sentinel](https://better-auth.com/docs/infrastructure/plugins/sentinel)

## 4. Server, client and developer surface

- **Server `auth.api`.** Every core and plugin endpoint is callable as a function with
  `body`/`headers`/`query`; `returnHeaders` and `asResponse` expose cookies/response objects;
  `APIError` should be checked with `isAPIError`. [API](https://better-auth.com/docs/concepts/api)
- **Client and hooks.** Framework clients (`better-auth/react`, `/vue`, `/svelte`, `/solid`,
  `/client`) share a framework-agnostic core; methods, `useSession`-style hooks, `fetchOptions`,
  session revalidation options, `$ERROR_CODES`, SSR `hydrateSession`, and client plugins.
  [Client](https://better-auth.com/docs/concepts/client)
- **Framework integrations.** Astro, React Router v7, Next.js, Nuxt, Electron, SvelteKit,
  SolidStart, TanStack Start, Waku; backend Hono, Fastify, Effect, Encore, Express, Elysia, Nitro,
  NestJS, Convex; mobile/desktop Expo and Lynx. [Documentation index](https://better-auth.com/docs/llms.txt)
- **Plugin architecture.** Server plugins contribute endpoints, schema, hooks, middleware,
  `onRequest`/`onResponse`, custom rate limits and trusted origins; client plugins infer endpoint
  methods and add actions/atoms for hooks. [Plugins](https://better-auth.com/docs/concepts/plugins)
- **Database adapters.** Built-in Kysely support for PostgreSQL/MySQL/SQLite/MSSQL, plus Drizzle,
  Prisma and MongoDB adapters and community adapters; migrations, runtime schema validation,
  configurable table/column names, `additionalFields`, ID generation strategies, database hooks
  and joins. [Database](https://better-auth.com/docs/concepts/database) · [Documentation index](https://better-auth.com/docs/llms.txt)
- **Hooks and middleware.** Global `before`/`after` middleware with a rich `ctx` (path, body,
  headers, cookies, new session, secret, hasher, adapter, internal adapter, `runInBackground`);
  database hooks on user/session/account/verification. [Hooks](https://better-auth.com/docs/concepts/hooks) · [Database](https://better-auth.com/docs/concepts/database)
- **Type inference.** `$Infer` on server and client, `additionalFields` with independent
  `input`/`returned` flags, `inferAdditionalFields` for monorepos and manual declarations for
  cross-repo clients. [TypeScript](https://better-auth.com/docs/concepts/typescript)
- **CLI.** `generate` (Prisma/Drizzle/Kysely schema), `migrate`, `check`/`check schema`,
  `create-admin`, `init`, `upgrade`, `secret`, `info`; programmatic `getMigrations` for Workers.
  [CLI](https://better-auth.com/docs/concepts/cli) · [Database](https://better-auth.com/docs/concepts/database)

## 5. Authentication plugins

Each line is one sentence plus the canonical page that owns it.

### 5.1 Alternative credentials and login methods

| Plugin | What it does |
| --- | --- |
| Two-factor | TOTP (authenticator apps) or emailed/SMS OTP as a second factor, with backup codes, trusted devices for 30 days, account lockout after repeated failures, and enforcement on credential sign-in endpoints. [Source](https://better-auth.com/docs/plugins/2fa) |
| Username | Sign up/sign in by username instead of email, with normalization, validators, `displayUsername`, availability checks and optional immutable usernames. [Source](https://better-auth.com/docs/plugins/username) |
| Anonymous | Passwordless/PII-free sessions with generated placeholder emails, later account linking via `onLinkAccount`, and a delete-anonymous-user endpoint. [Source](https://better-auth.com/docs/plugins/anonymous) |
| Phone number | SMS OTP verification, optional sign-up-on-verification, phone+password sign-in, phone-based password reset, update/remove phone, and brute-force attempt limits. [Source](https://better-auth.com/docs/plugins/phone-number) |
| Magic link | Passwordless email link sign-in, auto sign-up unless disabled, single-use atomic token redemption, configurable expiry and hashed/plain token storage. [Source](https://better-auth.com/docs/plugins/magic-link) |
| Email OTP | Email OTP for sign-in, email verification, password reset and change-email (including confirming the current address), with attempt limits and resend strategies. [Source](https://better-auth.com/docs/plugins/email-otp) |
| Passkey | WebAuthn/FIDO2 registration and sign-in (powered by SimpleWebAuthn), conditional UI, passkey-first onboarding, WebAuthn extensions and passkey management. [Source](https://better-auth.com/docs/plugins/passkey) |
| Generic OAuth | Any OAuth 2.0/OIDC provider registered as a first-class social provider, with discovery, PKCE and issuer validation by default, custom token/user-info hooks and OIDC RP-initiated logout. [Source](https://better-auth.com/docs/plugins/generic-oauth) |
| One Tap | Google One Tap prompt/button sign-in with ID-token audience verification, FedCM options, exponential-backoff retries and hosted-domain restrictions. [Source](https://better-auth.com/docs/plugins/one-tap) |
| SIWE | Ethereum wallet sign-in following ERC-4361: server-issued nonce, signed domain/address/chain/time validation, optional ENS lookup and wallet-address table. [Source](https://better-auth.com/docs/plugins/siwe) |
| One-time token | Generate and verify a short-lived single-use token bound to the current session, typically for cross-domain authentication. [Source](https://better-auth.com/docs/plugins/one-time-token) |

### 5.2 Authorization, tokens and account administration

| Plugin | What it does |
| --- | --- |
| Admin | Admin-only user management: create/list/update/delete users, roles and access control, ban/unban, session listing/revocation, impersonation, and `create-admin` CLI bootstrap. [Source](https://better-auth.com/docs/plugins/admin) |
| Organization | Organizations, members, teams, invitations, roles/permissions, active organization per session, and lifecycle hooks. [Source](https://better-auth.com/docs/plugins/organization) |
| API key | Create/verify/manage API keys with expiration, remaining counts and refill, metadata, prefixes, permissions, built-in rate limits, organization-owned keys, secondary storage and multiple configurations. [Source](https://better-auth.com/docs/plugins/api-key) |
| Bearer | Accept the session token as an `Authorization: Bearer` header instead of a cookie, optionally requiring the token to be signed. [Source](https://better-auth.com/docs/plugins/bearer) |
| JWT | Issue JWKS-verifiable session JWTs (`/token`, `set-auth-jwt`) for external services, with key rotation, asymmetric algorithms, custom signing/payloads and JWKS-backed cookie-cache signing. [Source](https://better-auth.com/docs/plugins/jwt) |
| Multi-session | Keep several accounts signed in simultaneously in one browser, with device-session listing, switching, revocation and a configurable maximum. [Source](https://better-auth.com/docs/plugins/multi-session) |
| Last login method | Track and display the last authentication method used (email, provider, passkey, SIWE, magic link, etc.) via cookie or a database field, with GDPR consent hooks. [Source](https://better-auth.com/docs/plugins/last-login-method) |
| Agent Auth | Agent registration/discovery and capability-based authorization with short-lived signed JWTs, OpenAPI/MCP adapters, device/CIBA approval and audit hooks (marked unstable by its docs). [Source](https://better-auth.com/docs/plugins/agent-auth) |

### 5.3 OAuth/OIDC provider and enterprise federation

| Plugin | What it does |
| --- | --- |
| OAuth 2.1 Provider | Turn the app into an OAuth 2.1/OIDC authorization server with authorization code + client credentials + rotating refresh tokens, PKCE, DPoP, introspection/revocation, discovery, consent and OIDC logout. [Source](https://better-auth.com/docs/plugins/oauth-provider) |
| Device Authorization | RFC 8628 device/user codes for TVs, CLIs and IoT, either for first-party session tokens or for OAuth access tokens when composed with the provider. [Source](https://better-auth.com/docs/plugins/device-authorization) |
| MCP | Make the app an OAuth authorization server and protected resource for Model Context Protocol clients, serving RFC 9728 metadata and verifying resource-bound JWTs/DPoP. [Source](https://better-auth.com/docs/plugins/mcp) |
| CIMD | Discover OAuth clients from HTTPS Client ID Metadata Documents with DNS-rebinding-safe fetching, caching/fetch budgets and origin-bound metadata rules. [Source](https://better-auth.com/docs/plugins/cimd) |
| SSO | Connect per-organization OIDC or SAML 2.0 identity providers at runtime, with discovery, `private_key_jwt`, SAML validation/Single Logout, provisioning, org provisioning and DNS domain verification. [Source](https://better-auth.com/docs/plugins/sso) |
| SCIM | Inbound SCIM 2.0 service letting a directory create/update/deactivate/delete users and groups, with transactional provisioning and SSO/role projection callbacks. [Source](https://better-auth.com/docs/plugins/scim) |

### 5.4 Abuse prevention, encryption-adjacent and UX plugins

| Plugin | What it does |
| --- | --- |
| Captcha | Bot protection on sign-up/sign-in/reset via Google reCAPTCHA, Cloudflare Turnstile, hCaptcha, CaptchaFox or Vercel BotID. [Source](https://better-auth.com/docs/plugins/captcha) |
| Have I Been Pwned | Reject compromised passwords at sign-up/password change using k-anonymous HIBP lookups (first five SHA-1 hash characters only). [Source](https://better-auth.com/docs/plugins/have-i-been-pwned) |
| i18n | Translate Better Auth error messages by locale (header/cookie/session/callback detection), with 22 bundled languages. [Source](https://better-auth.com/docs/plugins/i18n) |
| OAuth Proxy | Let local/preview deployments reuse the production OAuth callback with encrypted profile handoff and a dedicated shared proxy secret. [Source](https://better-auth.com/docs/plugins/oauth-proxy) |
| Sentinel (Infrastructure) | Managed abuse protection: credential stuffing, impossible travel, free-trial abuse, compromised-password checks, stale accounts, geo/bot/IP blocking, velocity limits and PoW challenges. [Source](https://better-auth.com/docs/infrastructure/plugins/sentinel) |
| Audit Logs (Infrastructure) | Automatic, queryable audit events for user, session, account, verification, organization and security activity. [Source](https://better-auth.com/docs/infrastructure/plugins/audit-logs) |

**Other index entries.** The index also lists Open API (endpoint reference generation), Test Utils
(integration/E2E helpers), Community Plugins, Other Social Providers/provider helpers, and guides.
Payments/billing plugins (Stripe, Polar, Autumn, Dodo, Creem, Chargebee, Commet), Dub lead tracking,
the infrastructure dashboard/marketing pages and email/SMS *managed services* are out of scope here
except where they implement a security control (Sentinel, audit logs, managed OTP delivery).

---

## 6. Capability mapping: Better Auth → Signet

| Feature | Better Auth source | Signet status | Notes |
| --- | --- | --- | --- |
| Email/password sign-up, sign-in, sign-out | [Email & Password](https://better-auth.com/docs/authentication/email-password) | already | Go API plus `/signup`, `/signin`, `/signout` HTTP endpoints. |
| Pluggable password hashing (default scrypt) | [Security](https://better-auth.com/docs/reference/security) | already | Argon2id default + bcrypt adapter, transparent rehash; different default algorithm. |
| Email verification with opt-in requirement | [Email](https://better-auth.com/docs/concepts/email) | already | `RequireVerifiedEmail` / `SendVerificationOnSignUp`; hashed single-use tokens. |
| Auto sign-in after sign-up / after verification | [Options](https://better-auth.com/docs/reference/options) | already | Opt-in Session issuance at Sign-up or verification; the original `SignUp`/`VerifyEmail` signatures are unchanged. |
| Email enumeration protection | [Security](https://better-auth.com/docs/reference/security) | already | Generic failures + dummy-hash timing parity; no synthetic-user response builder. |
| Password reset | [Email & Password](https://better-auth.com/docs/authentication/email-password) | already | Signet also revokes *all* sessions on reset (Better Auth's option is off by default). |
| Change password / set password / verify password | [Users & Accounts](https://better-auth.com/docs/concepts/users-accounts) | partial | `ChangePassword` is public, password-verified and revokes Sessions/Tokens; server-only `setPassword` and `verifyPassword` are not implemented. |
| Update user profile | [Users & Accounts](https://better-auth.com/docs/concepts/users-accounts) | partial | `UpdateUser` exists on the Store layer but is not exposed on `Client`. |
| Change email (verified new address, confirm current) | [Users & Accounts](https://better-auth.com/docs/concepts/users-accounts) | already | Two-phase `RequestEmailChange`/`VerifyEmailChange`; the new address is proven by a hashed single-use Token. Confirming via the current address is not implemented. |
| Delete user with verification | [Users & Accounts](https://better-auth.com/docs/concepts/users-accounts) | already | `RequestUserDeletion`/`DeleteUser` use an emailed single-use proof and explicit child deletion per ADR-0006. |
| `validateUserInfo` identity policy gate | [Users & Accounts](https://better-auth.com/docs/concepts/users-accounts) | partial | Verified-only OAuth auto-linking is enforced; no general policy callback. |
| Social OAuth (35+ built-in providers) | [OAuth](https://better-auth.com/docs/concepts/oauth) · [Index](https://better-auth.com/docs/llms.txt) | partial | Google and GitHub built in; `OAuthProvider` interface allows more without core changes. |
| OAuth PKCE and encrypted/expiring state | [Security](https://better-auth.com/docs/reference/security) | already | PKCE and encrypted, expiring, allowlisted state in Signet. |
| `mapProfileToUser`, ID-token sign-in, provider token refresh APIs | [OAuth](https://better-auth.com/docs/concepts/oauth) | partial | Provider mapping/ID-token handling are internal; no `getAccessToken`/`refreshToken`/`accountInfo`. |
| Account linking and unlinking | [Users & Accounts](https://better-auth.com/docs/concepts/users-accounts) | partial | Consent-based verified-only linking, safe account listing and guarded unlinking are public; no `trustedProviders`/`allowDifferentEmails` policy toggles. |
| Session list / revoke / revoke-all | [Session Management](https://better-auth.com/docs/concepts/session-management) | already | `ListSessions`, `RevokeSession`, `RevokeAllSessions`; no `revokeOtherSessions`. |
| Sliding session expiry (`expiresIn`/`updateAge`) | [Session Management](https://better-auth.com/docs/concepts/session-management) | partial | Signet has idle + absolute timeouts instead of sliding refresh. |
| Session freshness (`freshAge`) | [Session Management](https://better-auth.com/docs/concepts/session-management) | already | `Session.FreshAge`, `VerifyFreshSession` and `RequireFreshSession`, measured from `CreatedAt` per ADR-0005; account changes use a separate `Accounts.FreshWindow`. |
| Signed cookie cache (compact/JWT/JWE) | [Session Management](https://better-auth.com/docs/concepts/session-management) | partial | An opt-in `SessionCache` with bounded staleness and Store-authoritative revocation exists (ADR-0008); no compact/JWE cookie encoding. |
| Secondary storage (sessions, verification, rate limits) | [Database](https://better-auth.com/docs/concepts/database) | partial | A Redis-style Secondary store is an alternative `Store` implementation; no separate key/value interface or rate-limit counter storage. |
| Stateless cookie sessions | [Session Management](https://better-auth.com/docs/concepts/session-management) | partial | Signet's JWT mode is stateless for API clients but cookie sessions remain Store-backed. |
| Secure cookies, `HttpOnly`, `SameSite`, prefixes | [Cookies](https://better-auth.com/docs/concepts/cookies) | already | `__Host-` prefix where valid; `InsecureAllowHTTPCookies` must be opted into. |
| Cross-subdomain cookies | [Cookies](https://better-auth.com/docs/concepts/cookies) | partial | `Cookie.Domain` is configurable; no first-class cross-subdomain mode. |
| CSRF: origin checks + Fetch Metadata + signed double-submit | [Security](https://better-auth.com/docs/reference/security) | already | Signet uses a signed double-submit token plus `Origin`/`Sec-Fetch-Site`; equivalent outcome. |
| Trusted origins (wildcards/dynamic/custom schemes) | [Options](https://better-auth.com/docs/reference/options) | partial | Exact allowlists plus validated `https://*.example.com` Redirect patterns for OAuth and passwordless; no dynamic per-request functions or custom schemes, and CSRF same-origin is never widened. |
| Rate limiting with per-path rules and storage backends | [Rate Limit](https://better-auth.com/docs/concepts/rate-limit) | partial | Per-endpoint `RateLimitRules` and key prefixes are published and validated; the library ships no window-aware limiter or counter storage. |
| Proxy-aware IP handling and IPv6 subnet limits | [Rate Limit](https://better-auth.com/docs/concepts/rate-limit) | partial | Opt-in `TrustedProxies` CIDRs with right-to-left XFF walking and spoof protection; no IPv6 subnet normalization. |
| Token encryption at rest / secret rotation | [Options](https://better-auth.com/docs/reference/options) · [Security](https://better-auth.com/docs/reference/security) | partial | Digests for single-use proofs, encrypted OAuth state and TOTP secrets, plus ordered key rings for CSRF/JWT; no generic versioned-secret registry. |
| JWT access/refresh tokens with rotation | [JWT plugin](https://better-auth.com/docs/plugins/jwt) | already | Access/Refresh tokens, rotation, replay containment, key rings, opt-in JWKS with `kid`, and a Second-factor challenge gate on `/token`. |
| Bearer authentication from a session token | [Bearer](https://better-auth.com/docs/plugins/bearer) | partial | `VerifyAccessToken` + JWT mode serve API clients; no opaque-session bearer plugin. |
| `auth.api` server function surface | [API](https://better-auth.com/docs/concepts/api) | already | Typed `Client` methods are the Go equivalent (no HTTP round trip). |
| Client methods/hooks, framework adapters | [Client](https://better-auth.com/docs/concepts/client) | partial | Generated TS client + typed Go API; no framework hooks or reactive stores. |
| Plugin architecture (endpoints/schema/hooks) | [Plugins](https://better-auth.com/docs/concepts/plugins) | partial | Narrow interfaces (Store, Mailer, Hasher, RateLimiter, OAuthProvider) but no plugin system. |
| Database adapters and schema tooling | [Database](https://better-auth.com/docs/concepts/database) | partial | PostgreSQL/SQLite with explicit embedded migrations; no schema generator or ORM adapters. |
| Global and database hooks/middleware | [Hooks](https://better-auth.com/docs/concepts/hooks) | partial | Redacted `OnSignUp`/`OnSignIn` hooks + `RequireAuth`/`OptionalAuth`; no before/after pipeline. |
| Type inference from auth config | [TypeScript](https://better-auth.com/docs/concepts/typescript) | partial | Typed Go API and OpenAPI-generated TS client; no `$Infer` equivalent. |
| CLI schema generation/check | [CLI](https://better-auth.com/docs/concepts/cli) | partial | Explicit embedded migrations and `generate-check` for spec drift; no CLI. |
| Two-factor / passkey / magic link / email OTP / phone | [2FA](https://better-auth.com/docs/plugins/2fa) · [Passkey](https://better-auth.com/docs/plugins/passkey) · [Magic link](https://better-auth.com/docs/plugins/magic-link) · [Email OTP](https://better-auth.com/docs/plugins/email-otp) · [Phone](https://better-auth.com/docs/plugins/phone-number) | partial | TOTP Second factor with Backup codes, magic link, email OTP and passkeys are shipped; phone OTP is not. |
| Username / anonymous / one tap / SIWE / one-time token | [Username](https://better-auth.com/docs/plugins/username) · [Anonymous](https://better-auth.com/docs/plugins/anonymous) · [One Tap](https://better-auth.com/docs/plugins/one-tap) · [SIWE](https://better-auth.com/docs/plugins/siwe) · [OTT](https://better-auth.com/docs/plugins/one-time-token) | partial | Username sign-in is shipped as a `username` Account (ADR-0010); anonymous, One Tap, SIWE and one-time tokens are not. |
| Generic OAuth provider | [Generic OAuth](https://better-auth.com/docs/plugins/generic-oauth) | already | An `oauth/oidc` adapter implements discovery, PKCE and verified ID tokens on the existing `OAuthProvider` seam. |
| Admin / organization / API keys | [Admin](https://better-auth.com/docs/plugins/admin) · [Organization](https://better-auth.com/docs/plugins/organization) · [API Key](https://better-auth.com/docs/plugins/api-key) | already | Application-managed roles, digest-only API keys, organizations and guarded admin management are shipped. |
| OAuth/OIDC provider, device flow, MCP, CIMD | [OAuth Provider](https://better-auth.com/docs/plugins/oauth-provider) · [Device](https://better-auth.com/docs/plugins/device-authorization) · [MCP](https://better-auth.com/docs/plugins/mcp) · [CIMD](https://better-auth.com/docs/plugins/cimd) | partial | An opt-in Authorization server issues PKCE codes, rotating tokens and device authorizations. MCP, CIMD and DPoP are not shipped. |
| SAML/OIDC SSO and SCIM | [SSO](https://better-auth.com/docs/plugins/sso) · [SCIM](https://better-auth.com/docs/plugins/scim) | partial | Per-organization OIDC and SAML 2.0 SSO with verified domains and just-in-time provisioning, plus SCIM 2.0 User and Group provisioning, are shipped. Enterprise extension attributes are not supported. |
| Captcha / Have I Been Pwned / Sentinel | [Captcha](https://better-auth.com/docs/plugins/captcha) · [HIBP](https://better-auth.com/docs/plugins/have-i-been-pwned) · [Sentinel](https://better-auth.com/docs/infrastructure/plugins/sentinel) | partial | Opt-in Breach and Captcha checks are shipped; Sentinel-style anomaly detection is out of scope. |
| Audit logs / i18n / last login method | [Audit Logs](https://better-auth.com/docs/infrastructure/plugins/audit-logs) · [i18n](https://better-auth.com/docs/plugins/i18n) · [Last Login](https://better-auth.com/docs/plugins/last-login-method) | partial | An opt-in Audit sink and a signed Last sign-in method cookie are shipped; i18n is fully out of scope and Signet has no queryable audit log. |

## 7. Likely implementation order for Signet

Feature order follows dependencies: session primitives and user lifecycle first, then additional
first factors, then provider/enterprise surfaces, then defensive and operational extras. Effort is
relative for a small Go library that already has the Store and token primitives.

As of 2026-11-23, all six original phases below are **shipped** (PRs #53, #58, #65, #70, #76, #81,
#87 and #88), passkeys shipped as Phase 7, and automatic sign-in as Phase 8a. i18n and anomaly detection remain explicitly out of scope.

1. **Foundation — user lifecycle and session controls (shipped).**
   `ChangePassword`/`SetPassword`, `ChangeEmail`, `DeleteUser` with re-verification, and
   `freshAge` checks. These reuse existing token/session machinery and unlock later flows.
   Also add per-path rate-limit rules and proxy-aware IP keys (medium, **security-sensitive**).
2. **Session storage and token hardening (shipped).** Secondary storage
   abstraction (and its revocation/consistency semantics), signed cookie cache with a compact
   format, JWKS/key rotation for JWT mode, versioned secrets, and trusted-origin/wildcard
   handling. Cookie-cache revocation lag and secondary-storage failure modes need explicit tests.
3. **Passwordless first factors (shipped).** Magic link and email OTP
   first (they reuse the existing mailer and hashed single-use tokens), then username and TOTP
   2FA. Passkey is **shipped** as Phase 7: WebAuthn attestation/assertion verification is delegated
   to a pinned protocol library behind an internal package. Account-listing/unlinking belongs here.
4. **Broader federation (large, security-sensitive).** Generic OAuth/OIDC discovery on top of
   the existing `OAuthProvider` interface, then SSO (OIDC + SAML), OAuth provider/device flow and
   SCIM. Each has protocol-specific CSRF/replay rules that must be designed in, not bolted on.
5. **Authorization and management (shipped).** Admin roles/bans/impersonation, organizations and
   API keys. All state stays behind optional application-supplied interfaces; impersonation uses a
   signed cookie and a Store-backed Session.
6. **Defensive and operational extras (shipped except anomaly detection).** Breach checks, captcha checks, an Audit sink and Last sign-in method are opt-in interfaces. i18n is fully out of scope. Sentinel's
   device fingerprinting and impossible-travel detection are **large** and depend on external
   services, so they should be last and optional.

Explicitly avoid for a small embeddable library: bundling a dashboard, billing plugins or
framework-specific reactive hooks; those are Better Auth product surfaces, not authentication
capabilities Signet needs to match.

---

## Sources

**Indexes / version context**

- https://better-auth.com/llms.txt
- https://better-auth.com/docs/llms.txt

**Concepts and reference**

- https://better-auth.com/docs/authentication/email-password
- https://better-auth.com/docs/concepts/api
- https://better-auth.com/docs/concepts/cli
- https://better-auth.com/docs/concepts/client
- https://better-auth.com/docs/concepts/cookies
- https://better-auth.com/docs/concepts/database
- https://better-auth.com/docs/concepts/email
- https://better-auth.com/docs/concepts/hooks
- https://better-auth.com/docs/concepts/oauth
- https://better-auth.com/docs/concepts/plugins
- https://better-auth.com/docs/concepts/rate-limit
- https://better-auth.com/docs/concepts/session-management
- https://better-auth.com/docs/concepts/typescript
- https://better-auth.com/docs/concepts/users-accounts
- https://better-auth.com/docs/reference/options
- https://better-auth.com/docs/reference/security

**Plugins**

- https://better-auth.com/docs/plugins/2fa
- https://better-auth.com/docs/plugins/admin
- https://better-auth.com/docs/plugins/agent-auth
- https://better-auth.com/docs/plugins/anonymous
- https://better-auth.com/docs/plugins/api-key
- https://better-auth.com/docs/plugins/bearer
- https://better-auth.com/docs/plugins/captcha
- https://better-auth.com/docs/plugins/cimd
- https://better-auth.com/docs/plugins/device-authorization
- https://better-auth.com/docs/plugins/email-otp
- https://better-auth.com/docs/plugins/generic-oauth
- https://better-auth.com/docs/plugins/have-i-been-pwned
- https://better-auth.com/docs/plugins/i18n
- https://better-auth.com/docs/plugins/jwt
- https://better-auth.com/docs/plugins/last-login-method
- https://better-auth.com/docs/plugins/magic-link
- https://better-auth.com/docs/plugins/mcp
- https://better-auth.com/docs/plugins/multi-session
- https://better-auth.com/docs/plugins/oauth-provider
- https://better-auth.com/docs/plugins/oauth-proxy
- https://better-auth.com/docs/plugins/one-tap
- https://better-auth.com/docs/plugins/one-time-token
- https://better-auth.com/docs/plugins/organization
- https://better-auth.com/docs/plugins/passkey
- https://better-auth.com/docs/plugins/phone-number
- https://better-auth.com/docs/plugins/scim
- https://better-auth.com/docs/plugins/siwe
- https://better-auth.com/docs/plugins/sso
- https://better-auth.com/docs/plugins/username
- https://better-auth.com/docs/infrastructure/plugins/audit-logs
- https://better-auth.com/docs/infrastructure/plugins/sentinel
