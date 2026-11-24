# @shakibdshy/signet-react

Optional React session hooks for Signet: `SignetProvider`, `useSession()` and
`sessionGuard`. They wrap the framework-neutral
[`@shakibdshy/signet-client`](https://github.com/shakibdshy/signet/tree/main/client/ts) typed client, so components share one live Session
state instead of calling the API themselves.

Current version: **`1.0.0-beta`**. Both packages are released together at the same
version.

| Package | Version | Role |
| --- | --- | --- |
| `@shakibdshy/signet-client` | `1.0.0-beta` | Typed HTTP client, framework-neutral |
| `@shakibdshy/signet-react` | `1.0.0-beta` | Provider, hooks and route guard; depends on the client |

Full guide: [React session hooks](https://shakibdshy.github.io/signet/docs/react-hooks).

## Install

Published package — the typed client is installed automatically:

```sh
npm install @shakibdshy/signet-react@1.0.0-beta
```

From a local checkout of this repository, install both packages:

```sh
cd /path/to/signet/client/ts
npm install
npm run build

cd /path/to/your-frontend
npm install /path/to/signet/client/ts
npm install /path/to/signet/client/react
```

Requires React 18 or newer.

## Create the typed client

```ts
// signet-client.ts
import { createSignetClient } from "@shakibdshy/signet-client";

export const auth = createSignetClient({
  baseURL: "https://api.example.com/auth", // must include Config.PathPrefix
});
```

See the [client README](https://github.com/shakibdshy/signet/blob/main/client/ts/README.md) and the
[frontend guide](https://shakibdshy.github.io/signet/docs/frontend-client) for every
available method and the `baseURL` rules.

## Wrap your app

```tsx
// main.tsx
import { SignetProvider } from "@shakibdshy/signet-react";
import { auth } from "./signet-client";
import { App } from "./App";

export function Root() {
  return (
    <SignetProvider client={auth}>
      <App />
    </SignetProvider>
  );
}
```

The provider performs one `GET /me` request on mount and shares `status`, `user` and
`error` with every consumer.

## Use the session

```tsx
// Profile.tsx
import { useSession } from "@shakibdshy/signet-react";

export function Profile() {
  const { status, user, error, signIn, signOut, refresh } = useSession();

  if (status === "loading") return <p>Loading…</p>;
  if (error) return <p role="alert">{error.message}</p>;
  if (status === "anonymous") return <button onClick={() => signIn({ email: "a@b.com", password: "secret" })}>Sign in</button>;

  return (
    <>
      <p>Signed in as {user?.email}</p>
      <button onClick={() => refresh()}>Refresh</button>
      <button onClick={() => signOut()}>Sign out</button>
    </>
  );
}
```

`signIn` and `signOut` update the shared state, so every `useSession()` consumer
re-renders. Errors are the generated `SignetApiError` from the typed client.

## Protect a server-rendered route

```ts
// middleware.ts (Next.js example)
import { sessionGuard } from "@shakibdshy/signet-react";

export async function middleware(request: Request) {
  const ok = await sessionGuard(
    "https://api.example.com/auth",
    request.headers.get("cookie") ?? "",
  );
  if (!ok) return Response.redirect(new URL("/signin", request.url));
  return Response.next();
}

export const config = { matcher: ["/private/:path*"] };
```

`sessionGuard` appends `/me` to the configured base URL, preserving a `PathPrefix`. It
checks the incoming cookies and never creates a Session itself.

## Development

```sh
npm install
npm run typecheck
npm run build
```

The dependency is declared as a registry version in `package.json`; the lockfile keeps
a local `../ts` link so development in this checkout uses the current client source.
