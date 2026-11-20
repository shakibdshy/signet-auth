# @shakibdshy/signet-client

A generated TypeScript client for Signet's HTTP API. Types come from
`api/signet.openapi.json`, which is generated from the Go contract in
`internal/httpapi/contract.go`.

## Install

```sh
npm install @shakibdshy/signet-client
```

## Use

```ts
import { createSignetClient, SignetApiError } from "@shakibdshy/signet-client";

const auth = createSignetClient({ baseURL: "https://api.example.com" });

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

Cookies are included on every request. The CSRF token is fetched lazily from
`GET /csrf-token` (or from the sign-in response) and sent as `X-CSRF-Token` on
state-changing calls.

## In a separate frontend repo

The backend team publishes this package (or their own merged SDK) with a SemVer
version. The frontend installs it; a breaking server shape change is a major
version and fails the frontend build at the affected call sites. This is the
cross-repo equivalent of Hono RPC's `typeof app` — the compiler is the contract.

The generated types are framework-neutral. TanStack Start and Next.js apps can
use them directly, or layer Orval on the spec for TanStack Query hooks.

## Development

```sh
npm install
npm run generate   # regenerate src/schema.d.ts from ../../api/signet.openapi.json
npm run typecheck  # compile-time contract checks, including src/type-contracts.ts
npm run build      # emit dist/ for publishing
```
