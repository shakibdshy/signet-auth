import { createOpenAPI } from 'fumadocs-openapi/server';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Document } from 'fumadocs-openapi';

// The published spec deliberately has no `servers` entry — its base URL depends
// on where the application mounts Signet. For the docs playground only, inject a
// configurable default so "Send" doesn't fall back to https://example.com.
// The docs dev/build commands always run from the docs-site directory.
const specPath = resolve(process.cwd(), 'openapi/signet.openapi.json');

const backend = process.env.NEXT_PUBLIC_SIGNET_API_URL ?? 'http://localhost:8080/auth';

const loadSpec = (): Document => {
  const doc = JSON.parse(readFileSync(specPath, 'utf8')) as Document;
  return {
    ...doc,
    servers: [{ url: backend, description: 'Signet example backend' }],
  };
};

// Server-side API. The schema is loaded from the generated contract synced by
// `npm run sync:spec`, so the reference pages stay in step with the handlers.
export const openapi = createOpenAPI({
  input: { signet: loadSpec },
  // Keep playground requests same-origin; the proxy is allowlisted to the
  // configured backend so the browser never talks to an arbitrary host.
  proxyUrl: '/api/proxy',
});
