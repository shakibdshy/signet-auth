import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Document } from 'fumadocs-openapi';

const raw = process.env.NEXT_PUBLIC_SIGNET_API_URL || 'http://localhost:8080/auth';

function parseBackend(value: string): URL {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || !url.host) throw new Error('bad URL');
    return url;
  } catch {
    throw new Error('NEXT_PUBLIC_SIGNET_API_URL must be an absolute http(s) URL, e.g. http://localhost:8080/auth');
  }
}

/** Parsed once so the playground spec and the proxy allowlist cannot diverge. */
export const backendUrl = parseBackend(raw);
export const backendOrigin = backendUrl.origin;
const basePath = backendUrl.pathname.replace(/\/+$/, '');

const spec = JSON.parse(
  readFileSync(resolve(process.cwd(), 'openapi/signet.openapi.json'), 'utf8'),
) as Document;
const specPaths = new Set(Object.keys(spec.paths ?? {}));

/** True only for documented operations on the configured backend. */
export function isSpecRequest(url: URL): boolean {
  if (url.origin !== backendOrigin) return false;
  if (!url.pathname.startsWith(basePath + '/')) return false;
  return specPaths.has(url.pathname.slice(basePath.length));
}
