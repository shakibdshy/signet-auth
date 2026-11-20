# Signed double-submit CSRF protection

Signet protects browser state changes with a signed double-submit cookie: an HMAC-signed random token is set in a readable cookie and required in the `X-CSRF-Token` header, alongside the existing `Origin` and `Sec-Fetch-Site` checks. Signing prevents subdomain cookie injection, and the token is stateless so Signet needs no server-side session for CSRF state.

We rejected server-side synchronizer tokens because they require per-session server state, which conflicts with the goal of a small, embeddable library that works with any Store. The trade-off is that the token lives in a readable cookie, so any script that can read it can also use it — but such a script can already make same-origin requests, so this does not weaken the session cookie. Applications with stricter requirements can layer additional protections.
