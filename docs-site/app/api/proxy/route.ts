import { openapi } from '@/lib/openapi';
import { backendOrigin, isSpecRequest } from '@/lib/backend';

// Same-origin proxy for the API playground. It relays only documented
// operations on the configured backend origin — not arbitrary paths.
const proxy = openapi.createProxy({
  allowedOrigins: [backendOrigin],
  filterRequest: (request) => isSpecRequest(new URL(request.url)),
});

// The playground forwards each operation's own HTTP method through the proxy.
export const { GET, POST, PUT, PATCH, DELETE, HEAD } = proxy;
