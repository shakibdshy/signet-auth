import { createOpenAPI } from 'fumadocs-openapi/server';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Document } from 'fumadocs-openapi';
import { backendUrl } from './backend';

// The published spec deliberately has no `servers` entry — its base URL depends
// on where the application mounts Signet. For the docs playground only, inject a
// configurable default so "Send" doesn't fall back to https://example.com.
// The docs dev/build commands always run from the docs-site directory.
const specPath = resolve(process.cwd(), 'openapi/signet.openapi.json');

const loadSpec = (): Document => {
  const doc = JSON.parse(readFileSync(specPath, 'utf8')) as Document;
  return {
    ...doc,
    servers: [{ url: backendUrl.toString(), description: 'Signet example backend' }],
  };
};

/** The accordion each API endpoint belongs to in the reference sidebar. */
export function referenceGroup(route: string): string {
  const path = route.replace(/^\//, '');
  if (path.startsWith('passkeys')) return 'Passkeys';
  if (path.startsWith('admin-user') || path === 'impersonate' || path === 'stop-impersonating') return 'Admin users';
  if (path.startsWith('organization') || path.includes('active-organization') || path === 'clear-active-organization') return 'Organizations';
  if (path.startsWith('api-keys') || path.startsWith('revoke-api-key') || path === 'verify-api-key') return 'API keys';
  if (path.startsWith('oauth/') || path === 'last-sign-in-method') return 'OAuth and federation';
  if (path.includes('two-factor') || path === 'regenerate-backup-codes') return 'Second factor';
  if (path === 'send-magic-link' || path === 'verify-magic-link' || path === 'send-otp' || path === 'verify-otp') return 'Passwordless';
  if (path === 'signup' || path === 'signin' || path === 'signout' || path === 'token') return 'Authentication';
  if (path === 'sessions' || path === 'session') return 'Sessions';
  if (path === 'accounts' || path === 'unlink-account') return 'Accounts';
  if (path === 'csrf-token') return 'Utilities';
  return 'Email and verification';
}

/** Flat file name inside an accordion; operationIds can contain slashes. */
export function referenceName(route: string, method: string): string {
  const path = route.replace(/^\//, '').replace(/\//g, '-');
  return `${path}_${method.toLowerCase()}`;
}

// Server-side API. The schema is loaded from the generated contract synced by
// `npm run sync:spec`, so the reference pages stay in step with the handlers.
export const openapi = createOpenAPI({
  input: { signet: loadSpec },
  proxyUrl: '/api/proxy',
});
