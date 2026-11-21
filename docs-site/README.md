# Signet documentation site

Built with [Fumadocs](https://fumadocs.dev) on Next.js. It is a self-contained
subproject: it has its own `package.json`, lockfile and CI job, and the Go build
does not depend on it.

## Commands

```bash
npm install
npm run sync:spec   # copy ../api/signet.openapi.json into openapi/
npm run types:check
npm run dev         # http://localhost:3000/docs
npm run build
```

`npm run sync:spec` must be run after changing the Go HTTP contract and running
`make generate`. The OpenAPI reference pages are generated at build time from
`openapi/signet.openapi.json` — they are not hand-written.

## Playground base URL

The published spec has no `servers` entry, because Signet can be mounted under any
prefix. The docs site injects one for the playground only. Set
`NEXT_PUBLIC_SIGNET_API_URL` to the full endpoint prefix of your backend; it
defaults to `http://localhost:8080/auth`, which is where the bundled stdlib
example mounts `auth.Handler()`:

```bash
NEXT_PUBLIC_SIGNET_API_URL=http://localhost:8080/auth npm run dev
```

Playground requests go through the same-origin `/api/proxy` route, which is
allowlisted to that backend origin so it cannot be used as an open proxy. For a
deployed docs site, set the variable to your public API origin before building.

Note that authenticated endpoints still need a session cookie. The playground
does not manage cookies, so use the docs reference for request/response shapes
and a real client (the generated TypeScript client) for end-to-end flows.

## Content

- `content/docs/` — guides (quickstart, sessions, OAuth, JWT, frontend client).
- `openapi/signet.openapi.json` — generated contract, synced from the repository.
- `lib/openapi.ts` — the server-side Fumadocs OpenAPI source.
- `lib/source.ts` — combines MDX guides with the virtual OpenAPI pages.

See `AGENTS.md` in this folder for Fumadocs-specific documentation links.
