# Signet React hooks

**React session hooks for [Signet](https://github.com/shakibdshy/signet-auth), an authentication library written in Go.**

Signet's auth logic runs in your Go backend. The typed client `@shakibdshy/signet-auth-client`
calls its HTTP API from a frontend, and this package is the React layer on top of that client:
`SignetProvider`, `useSession()` and `sessionGuard`. Your components read one shared Session
state instead of each one calling the Go API on its own.

| Part of Signet | Runs in | Written in | Package |
| --- | --- | --- | --- |
| The auth logic: passwords, Sessions, OAuth, mail, security checks | Your backend | Go | `github.com/shakibdshy/signet-auth` |
| Calls that backend from a frontend | Browser, Node.js | TypeScript, JavaScript | `@shakibdshy/signet-auth-client` |
| **Shares that Session with React components and guards routes** | Browser | TypeScript, React | **`@shakibdshy/signet-auth-react`** (this package) |

Current version: **`1.0.0-beta`**, a pre-1.0 release, so the API may still change before
`v1.0.0`. The Go module (`v1.0.0-beta`) and both npm packages (`1.0.0-beta`) are released
together at the same version.

> **This package does not implement authentication.** It is a thin layer over the typed
> client, and every request still goes to the Signet handler in your Go backend. To set that
> backend up, start with the [Signet README for Go](https://github.com/shakibdshy/signet-auth).

## Which package do you need?

- **Any frontend other than React**, or a React app that manages Session state itself:
  install only
  [`@shakibdshy/signet-auth-client`](https://github.com/shakibdshy/signet-auth/tree/main/client/ts).
- **React, when you want your components to share one Session state and to guard routes:**
  install this package. It depends on the client at the same version, so npm installs both.

## Requirements

- **React 18 or newer.** The client needs Node.js 20 or newer.
- **A backend that runs Signet.**
- **Same origin.** Signet keeps Sessions in cookies and requires same-origin requests for
  CSRF protection, so a cross-origin fetch cannot use a cookie Session. Serve your app and
  the Go handler from one origin, or route requests through a same-origin proxy.

## Install

```sh
npm install @shakibdshy/signet-auth-react@1.0.0-beta
```

This also installs `@shakibdshy/signet-auth-client`. Do not install the client separately.

To use a change that is not published yet, install both packages from a checkout of the
repository:

```sh
cd /path/to/signet-auth/client/ts
npm install
npm run build

cd /path/to/signet-auth/client/react
npm install
npm run build

cd /path/to/your-frontend
npm install /path/to/signet-auth/client/ts
npm install /path/to/signet-auth/client/react
```

## Quick start

### 1. Create the typed client

```ts
// signet-auth-client.ts
import { createSignetClient } from "@shakibdshy/signet-auth-client";

export const auth = createSignetClient({
  // Your backend's origin, plus the prefix where it mounts Signet.
  baseURL: "https://api.example.com/auth",
});
```

Every method of the client is described in the
[client README](https://github.com/shakibdshy/signet-auth/blob/main/client/ts/README.md).

### 2. Wrap your app in the provider

```tsx
// main.tsx
import { SignetProvider } from "@shakibdshy/signet-auth-react";
import { auth } from "./signet-auth-client";
import { App } from "./App";

export function Root() {
  return (
    <SignetProvider client={auth}>
      <App />
    </SignetProvider>
  );
}
```

On mount, the provider makes one `GET /me` request to the Go backend and shares the result
with every `useSession()` call under it.

### 3. Use the Session in a component

```tsx
// Profile.tsx
import { useState } from "react";
import { useSession } from "@shakibdshy/signet-auth-react";

export function Profile() {
  const { status, user, signIn, signOut } = useSession();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [formError, setFormError] = useState("");

  if (status === "loading") return <p>Loading…</p>;

  if (status === "anonymous") {
    return (
      <form onSubmit={async (event) => {
        event.preventDefault();
        setFormError("");
        try {
          await signIn({ email, password });
        } catch {
          setFormError("Invalid email or password.");
        }
      }}>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button type="submit">Sign in</button>
        {formError && <p role="alert">{formError}</p>}
      </form>
    );
  }

  return (
    <>
      <p>Signed in as {user?.email}</p>
      <button onClick={() => signOut()}>Sign out</button>
    </>
  );
}
```

`signIn` and `signOut` update the shared state, so every `useSession()` call re-renders.

### 4. Protect a server-rendered route

```ts
// middleware.ts (Next.js example)
import { sessionGuard } from "@shakibdshy/signet-auth-react";

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

`sessionGuard` appends `/me` to the URL you pass, so that URL must include the prefix where
the backend mounts Signet. It forwards the request's cookies and never creates a Session.

## What useSession() returns

| Field | What it is |
| --- | --- |
| `status` | `"loading"`, `"authenticated"` or `"anonymous"`. It starts as `"loading"` and changes when the first `GET /me` finishes. |
| `user` | The signed-in User returned by `GET /me`, or `null`. |
| `error` | The `SignetApiError` from the last failed `GET /me`, or `null`. |
| `signIn(input)` | Calls the client's `signIn`, then reads the Session again. It throws the client's error if sign-in fails. |
| `signOut()` | Calls the client's `signOut`, then sets `status` to `"anonymous"`. |
| `refresh()` | Calls `GET /me` again and updates `status`, `user` and `error`. |

Branch on `status`, not on `error`. The backend answers `GET /me` with 401 for a visitor who
is not signed in, so for that visitor `status` is `"anonymous"` and `error` holds that 401.

Two limits to know about:

- `SignetProvider` makes its request after mount, so server-rendered HTML shows the
  `"loading"` state.
- `signIn` does not handle a Second factor yet. If the backend asks for one, no Session is
  created and `status` stays `"anonymous"`.

## Learn more

- [React session hooks guide](https://shakibdshy.github.io/signet-auth/docs/react-hooks): the
  full walkthrough.
- [Client README](https://github.com/shakibdshy/signet-auth/blob/main/client/ts/README.md) and
  [frontend client guide](https://shakibdshy.github.io/signet-auth/docs/frontend-client): every
  client method and the `baseURL` rules.
- [Signet README for Go](https://github.com/shakibdshy/signet-auth): features, quickstart and
  backend setup.

## Development

The package lives in
[`client/react`](https://github.com/shakibdshy/signet-auth/tree/main/client/react) in the
Signet repository.

```sh
npm install
npm run typecheck
npm run build
```

The dependency on the client is declared as a registry version in `package.json`; the
lockfile keeps a local `../ts` link so development in this checkout uses the current client
source.

## License

[MIT](https://github.com/shakibdshy/signet-auth/blob/main/LICENSE)
