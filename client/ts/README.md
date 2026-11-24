# @shakibdshy/signet-client

A framework-neutral, generated TypeScript client for Signet's HTTP API. Types come from
`api/signet.openapi.json`, which is generated from the Go contract in
`internal/httpapi/contract.go`, so method signatures and error codes match the server.

Current version: **`1.0.0-beta`**. The optional
[`@shakibdshy/signet-react`](https://github.com/shakibdshy/signet/tree/main/client/react) hooks package is released at the same version and
depends on this client.

Full guides: [Frontend client](https://shakibdshy.github.io/signet/docs/frontend-client)
and [React session hooks](https://shakibdshy.github.io/signet/docs/react-hooks).

## Why this package exists

Signet is an **embeddable Go library**, not a hosted auth service. A Go application imports
it, mounts `signet.Client.Handler()` under a `Config.PathPrefix` (for example `/auth`),
and keeps its own database and router. There is no separate auth server to install.

This package exists so a browser or Node frontend can call that Go handler with real types:

```text
Go application
  └─ signet.Client.Handler() under Config.PathPrefix
       └─ HTTP contract (internal/httpapi/contract.go)
            └─ api/signet.openapi.json
                 └─ @shakibdshy/signet-client  ← this package
                      └─ @shakibdshy/signet-react (optional React binding)
```

The client and its error codes are generated from Signet's OpenAPI spec, which is
generated from the Go contract. A server shape change makes the frontend fail to compile
at the affected call sites — the compiler is the contract. A `make generate-check` in the
Go repository prevents the spec and generated types from drifting apart.

The Go module (`v1.0.0-beta`), this package (`1.0.0-beta`), and the React package
(`1.0.0-beta`) are released together at the same version. Go libraries are distributed by
a semver git tag and the Go module proxy, not through npm; these two npm packages are the
frontend counterparts of that same release.

**Which package do you need?** Use this one for any TypeScript or JavaScript frontend,
including Vue, Svelte, TanStack Start and Next.js. Use
[`@shakibdshy/signet-react`](https://github.com/shakibdshy/signet/tree/main/client/react)
only if you also want reactive session state in React; it depends on this client.

Because Signet uses `__Host-` cookies and same-origin CSRF, the frontend must reach the Go
handler on the same origin or through a same-origin proxy — a cross-origin fetch cannot
use cookie Sessions.

## Install

Published package:

```sh
npm install @shakibdshy/signet-client@1.0.0-beta
```

From a local checkout of this repository:

```sh
cd /path/to/signet/client/ts
npm install
npm run build

cd /path/to/your-frontend
npm install /path/to/signet/client/ts
```

Requires Node.js 20 or newer.

## Use

```ts
import { createSignetClient, SignetApiError } from "@shakibdshy/signet-client";

export const auth = createSignetClient({
  // Origin + your backend's Config.PathPrefix. If the Go server mounts
  // auth.Handler() at /auth, baseURL MUST include /auth.
  baseURL: "https://api.example.com/auth",
});

const { user } = await auth.signUp({
  email: "user@example.com",
  password: "correct horse battery staple",
  name: "Ada",
});

try {
  await auth.signIn({ email: "user@example.com", password: "wrong" });
} catch (err) {
  if (err instanceof SignetApiError && err.code === "invalid_credentials") {
    // show a generic sign-in error
  }
}
```

> **Most common mistake:** using only `https://api.example.com` as `baseURL` when the
> backend mounts Signet at `/auth`. The generated client calls `/signup`, so without the
> prefix every request goes to `https://api.example.com/signup` and returns 404.

Cookies are included on every request. The CSRF token is fetched lazily from
`GET /csrf-token` (or from the sign-in response) and sent as `X-CSRF-Token` on
state-changing calls. You do not manage CSRF yourself.

The generated types are framework-neutral. TanStack Start and Next.js apps can use them
directly, or layer Orval on the spec for TanStack Query hooks.

## Development

```sh
npm install
npm run generate   # regenerate src/schema.d.ts from ../../api/signet.openapi.json
npm run typecheck  # compile-time contract checks, including src/type-contracts.ts
npm run build      # emit dist/ for publishing
```

The HTTP contract lives in `internal/httpapi/contract.go`; `make generate-check` at the
repository root verifies the published spec and generated types cannot drift from it.
