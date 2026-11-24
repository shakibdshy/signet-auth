# @shakibdshy/signet-client

A framework-neutral, generated TypeScript client for Signet's HTTP API. Types come from
`api/signet.openapi.json`, which is generated from the Go contract in
`internal/httpapi/contract.go`, so method signatures and error codes match the server.

Current version: **`1.0.0-beta`**. The optional
[`@shakibdshy/signet-react`](https://github.com/shakibdshy/signet/tree/main/client/react) hooks package is released at the same version and
depends on this client.

Full guides: [Frontend client](https://shakibdshy.github.io/signet/docs/frontend-client)
and [React session hooks](https://shakibdshy.github.io/signet/docs/react-hooks).

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
