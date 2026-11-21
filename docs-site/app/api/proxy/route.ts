import { openapi } from '@/lib/openapi';

// Same-origin proxy for the API playground. Only the configured Signet backend
// origin is allowed — without an allowlist this would be an open proxy.
const proxy = openapi.createProxy({
  allowedOrigins: [new URL(process.env.NEXT_PUBLIC_SIGNET_API_URL ?? 'http://localhost:8080/auth').origin],
});

// The playground forwards each operation's own HTTP method through the proxy,
// so the route must accept every method it might send.
export const { GET, POST, PUT, PATCH, DELETE, HEAD } = proxy;
