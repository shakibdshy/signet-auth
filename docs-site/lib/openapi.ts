import { createOpenAPI } from 'fumadocs-openapi/server';

// OpenAPI reference is generated from Signet's contract artifact, synced into
// this folder by `npm run sync:spec`. It is a server-side API.
export const openapi = createOpenAPI({
  input: ['./openapi/signet.openapi.json'],
});
