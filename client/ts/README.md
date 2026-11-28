# Signet TypeScript client

**The frontend client for [Signet](https://github.com/shakibdshy/signet-auth), an authentication library written in Go.**

Signet runs on the server, inside a Go application. This package is the frontend half: a
typed TypeScript client for the HTTP API that Signet serves from your backend. Use it from
a browser or Node.js to sign Users up and in, read and end Sessions, and reach Signet's
password reset, passwordless, Passkey, OAuth, SSO, organization, API key and admin features.
It attaches cookies and the CSRF token, so your frontend never builds those requests by hand.

| Part of Signet | Runs in | Written in | Package |
| --- | --- | --- | --- |
| The auth logic: passwords, Sessions, OAuth, mail, security checks | Your backend | Go | `github.com/shakibdshy/signet-auth` |
| **Calls that backend from a frontend** | Browser, Node.js | TypeScript, JavaScript | **`@shakibdshy/signet-auth-client`** (this package) |
| Shares the Session with React components and guards routes (optional) | Browser | TypeScript, React | `@shakibdshy/signet-auth-react` |

Current version: **`1.0.0-beta.3`**, a pre-1.0 release, so the API may still change before
`v1.0.0`. The Go module (`v1.0.0-beta.3`) and both npm packages (`1.0.0-beta.3`) are released
together at the same version.

> **This package does not implement authentication.** Every request goes to the Signet
> handler in your Go backend, so it has nothing to call without one. To set that backend up,
> start with the [Signet README for Go](https://github.com/shakibdshy/signet-auth).

## Which package do you need?

- **Any TypeScript or JavaScript frontend**, including React, Vue, Svelte, Next.js and
  TanStack Start: use this package.
- **React, when you want your components to share one Session state:** add
  [`@shakibdshy/signet-auth-react`](https://github.com/shakibdshy/signet-auth/tree/main/client/react).
  It installs this client for you and adds `SignetProvider`, `useSession()` and
  `sessionGuard` on top.

Signet is an embeddable Go library, not a hosted auth service. Your backend imports it,
mounts its handler under a path prefix such as `/auth`, and keeps its own database. There is
no separate auth server to install.

## Requirements

- **Node.js 20 or newer.**
- **A backend that runs Signet.**
- **Same origin.** Signet keeps Sessions in cookies and requires same-origin requests for
  CSRF protection, so a cross-origin fetch cannot use a cookie Session. Serve your frontend
  and the Go handler from one origin, or route requests through a same-origin proxy.

## Install

```sh
npm install @shakibdshy/signet-auth-client@1.0.0-beta.3
```

To use a change that is not published yet, install from a checkout of the repository:

```sh
cd /path/to/signet-auth/client/ts
npm install
npm run build

cd /path/to/your-frontend
npm install /path/to/signet-auth/client/ts
```

## Quick start

```ts
import { createSignetClient, SignetApiError } from "@shakibdshy/signet-auth-client";

export const auth = createSignetClient({
  // Your backend's origin, plus the prefix where it mounts Signet.
  // If the Go server mounts the handler at /auth, this must end with /auth.
  baseURL: "https://api.example.com/auth",
});

// Create an account. name is required.
await auth.signUp({
  email: "user@example.com",
  password: "correct horse battery staple",
  name: "Ada",
});

// Sign in. The Go backend sets the Session cookie; you never handle it.
await auth.signIn({ email: "user@example.com", password: "correct horse battery staple" });

// Read the signed-in User. The profile carries the verification state,
// the Username (empty when there is none) and the timestamps.
const user = await auth.me();

// Sign out.
await auth.signOut({});
```

Each call sends cookies and throws a `SignetApiError` when the backend returns an error
response.

```ts
try {
  await auth.signIn({ email: "user@example.com", password: "wrong" });
} catch (err) {
  if (err instanceof SignetApiError && err.code === "invalid_credentials") {
    // Show a generic sign-in error.
  }
}
```

A `SignetApiError` carries the backend's `code` (for example `invalid_credentials`,
`rate_limited` or `two_factor_required`), its `message`, and the HTTP `status`. All codes
are listed in the [error reference](https://shakibdshy.github.io/signet-auth/docs/errors).

> **Most common mistake:** using only `https://api.example.com` as `baseURL` when the
> backend mounts Signet at `/auth`. This client calls `/signup`, so without the prefix every
> request goes to `https://api.example.com/signup` and returns 404.

### Options

| Option | Required | What it does |
| --- | --- | --- |
| `baseURL` | Yes | Your backend's origin plus the prefix where it mounts Signet, for example `https://api.example.com/auth`. |
| `fetch` | No | A custom `fetch` implementation, mainly for tests. |
| `csrfToken` | No | A CSRF token you already have. Without it, the client fetches one from `GET /csrf-token` the first time it is needed. |

### What the client handles for you

- **Cookies.** Every request sends cookies (`credentials: "include"`), so the Session cookie
  that the Go backend sets is used on later calls.
- **CSRF.** The client fetches a token from `GET /csrf-token`, or reuses the one returned by
  sign-in, and sends it as `X-CSRF-Token` on the calls that require it.

## What you can call

The client has a typed method for most of Signet's HTTP API. The main methods by area:

| Area | Main methods |
| --- | --- |
| Sign-up, sign-in and sign-out | `signUp`, `signIn`, `signOut`, `me`, `lastSignInMethod` |
| JWT Access and Refresh tokens, when the backend enables them | `exchangeToken` |
| Sessions | `listSessions`, `revokeSession`, `revokeAllSessions` — each listed Session carries `user_agent`, the raw browser header it was started from |
| Email verification and passwords | `sendVerification`, `verifyEmail`, `sendPasswordReset`, `resetPassword`, `changePassword`, `changeEmail`, `verifyChangeEmail` |
| Linked provider accounts | `listAccounts`, `unlinkAccount` |
| Second factor | `enableTwoFactor`, `verifyTwoFactor`, `disableTwoFactor`, `regenerateBackupCodes` |
| Account deletion | `requestAccountDeletion`, `confirmAccountDeletion` |
| Passwordless sign-in | `sendMagicLink`, `verifyMagicLink`, `sendOtp`, `verifyOtp` |
| Passkeys | `beginPasskeyRegistration`, `finishPasskeyRegistration`, `beginPasskeySignIn`, `finishPasskeySignIn`, `listPasskeys`, `deletePasskey` |
| OAuth sign-in with Google, GitHub or a generic OIDC provider | `oauthStart` |
| Authorization server and device authorization | `oauthAuthorize`, `oauthToken`, `beginDeviceAuthorization`, `approveDeviceAuthorization`, `deviceToken` |
| Organization SSO and SAML | `startSSOSignIn`, `completeSSOSignIn`, `listSSOConnections`, `createSSOConnection`, `deleteSSOConnection`, `startSAMLSignIn` |
| Organizations | `createOrganization`, `listOrganizations`, `listOrganizationMembers`, `addOrganizationMember`, `removeOrganizationMember`, `setOrganizationMemberRole`, `setActiveOrganization`, `activeOrganization`, `clearActiveOrganization` |
| API keys | `createApiKey`, `listApiKeys`, `verifyApiKey`, `revokeApiKey` |
| Admin actions and impersonation | `adminListUsers`, `adminSetUserRole`, `adminBanUser`, `adminUnbanUser`, `adminListUserSessions`, `adminRevokeUserSession`, `impersonate`, `stopImpersonating` |

**One endpoint is intentionally not wrapped:** `POST /saml/acs` receives the SAML assertion
posted by the identity provider's browser redirect, so your frontend never calls it.

## How it stays in sync with the Go API

Signet's HTTP API is defined once, in the Go source. Signet generates an OpenAPI document
from that definition, and this package generates its request and response types from the
document. CI in the Go repository fails if the three drift apart. So when the Go API
changes, the types here change with it, and your build fails at the affected call instead of
at runtime.

## Learn more

- [Frontend client guide](https://shakibdshy.github.io/signet-auth/docs/frontend-client): every
  method, with examples for sign-in forms, passwordless sign-in, OAuth, Passkeys and more.
- [React session hooks guide](https://shakibdshy.github.io/signet-auth/docs/react-hooks) and
  the [React package README](https://github.com/shakibdshy/signet-auth/tree/main/client/react).
- [HTTP API reference](https://shakibdshy.github.io/signet-auth/docs/openapi): every endpoint.
- [Signet README for Go](https://github.com/shakibdshy/signet-auth): features, quickstart and
  backend setup.

## Development

The client lives in
[`client/ts`](https://github.com/shakibdshy/signet-auth/tree/main/client/ts) in the Signet
repository.

```sh
npm install
npm run generate   # regenerate src/schema.d.ts from ../../api/signet.openapi.json
npm run typecheck  # compile-time contract checks, including src/type-contracts.ts
npm run build      # emit dist/ for publishing
```

The HTTP contract lives in `internal/httpapi/contract.go`. `make generate-check` at the
repository root verifies that the published spec and the generated types match it.

## License

[MIT](https://github.com/shakibdshy/signet-auth/blob/main/LICENSE)
