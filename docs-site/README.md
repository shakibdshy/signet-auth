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

## Content

- `content/docs/` — guides (quickstart, sessions, OAuth, JWT, frontend client).
- `openapi/signet.openapi.json` — generated contract, synced from the repository.
- `lib/openapi.ts` — the server-side Fumadocs OpenAPI source.
- `lib/source.ts` — combines MDX guides with the virtual OpenAPI pages.

See `AGENTS.md` in this folder for Fumadocs-specific documentation links.
