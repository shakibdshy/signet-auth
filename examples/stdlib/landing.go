package main

import "net/http"

// landingHTML is served at / so that anyone opening the deployed origin sees
// what runs here and where to go next.
const landingHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signet Auth API</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #0d1117; color: #e6edf3; line-height: 1.6;
    display: flex; justify-content: center; padding: 4rem 1.5rem;
  }
  main { max-width: 720px; width: 100%; }
  .badge {
    display: inline-flex; align-items: center; gap: .5rem;
    font-size: .8rem; color: #7ee787; background: #12261a;
    border: 1px solid #1f4429; border-radius: 999px; padding: .25rem .8rem;
  }
  .dot { width: .5rem; height: .5rem; border-radius: 50%; background: #3fb950; }
  h1 { font-size: 1.9rem; margin: 1.2rem 0 .5rem; }
  h2 { font-size: 1rem; text-transform: uppercase; letter-spacing: .08em;
       color: #8b949e; margin: 2.2rem 0 .8rem; }
  p.lead { color: #a5adb6; }
  p.lead strong { color: #e6edf3; }
  ul.links { list-style: none; padding: 0; }
  ul.links li { padding: .15rem 0; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  table { width: 100%; border-collapse: collapse; font-size: .92rem; }
  td { padding: .45rem 0; border-bottom: 1px solid #21262d; vertical-align: top; }
  td:last-child { color: #a5adb6; }
  code {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    background: #161b22; border: 1px solid #21262d; border-radius: 6px;
    padding: .1rem .4rem; font-size: .85em; white-space: nowrap;
  }
  code.m { color: #7ee787; }
  footer { margin-top: 2.5rem; font-size: .82rem; color: #8b949e; }
</style>
</head>
<body>
<main>
  <span class="badge"><span class="dot"></span> operational</span>
  <h1>Signet Auth API</h1>
  <p class="lead">
    This is a live deployment of <strong>Signet</strong>, a secure-by-default,
    embeddable authentication library for Go. Signet runs inside this service;
    there is no separate auth server. Every account, session and token below is
    served by the same library your application would import.
  </p>

  <h2>Endpoints</h2>
  <table>
    <tr><td><code><span class="m">GET</span> /healthz</code></td><td>uptime probe</td></tr>
    <tr><td><code><span class="m">GET</span> /auth/csrf-token</code></td><td>CSRF token for state-changing calls</td></tr>
    <tr><td><code><span class="m">POST</span> /auth/signup</code></td><td>create an account</td></tr>
    <tr><td><code><span class="m">POST</span> /auth/signin</code></td><td>sign in (rotates the CSRF token)</td></tr>
    <tr><td><code><span class="m">POST</span> /auth/signout</code></td><td>revoke the session</td></tr>
    <tr><td><code><span class="m">GET</span> /auth/last-sign-in-method</code></td><td>how this browser last signed in</td></tr>
    <tr><td><code><span class="m">GET</span> /auth/organizations</code></td><td>list the caller's organizations</td></tr>
    <tr><td><code><span class="m">POST</span> /auth/organizations</code></td><td>create an organization (creator becomes owner)</td></tr>
    <tr><td><code><span class="m">GET</span> /auth/organization-members</code></td><td>list members (owner/admin)</td></tr>
    <tr><td><code><span class="m">POST</span> /auth/organization-members/add</code></td><td>add a member (owner/admin)</td></tr>
    <tr><td><code><span class="m">POST</span> /auth/organization-members/role</code></td><td>change a member's role (owner/admin)</td></tr>
    <tr><td><code><span class="m">POST</span> /auth/organization-members/remove</code></td><td>remove a member (owner/admin)</td></tr>
    <tr><td><code><span class="m">GET</span> /auth/demo/inbox?email=</code></td><td>demo inbox: recent emails for that address (DEMO_MODE)</td></tr>
    <tr><td><code><span class="m">GET</span> /private</code></td><td>protected route, requires a session cookie</td></tr>
  </table>

  <h2>Go further</h2>
  <ul class="links">
    <li><a href="https://github.com/shakibdshy/signet-auth">GitHub repository</a></li>
    <li><a href="https://github.com/shakibdshy/signet-auth#five-minute-quickstart">Five-minute quickstart</a></li>
    <li><a href="https://go-signet-auth.vercel.app/">Documentation</a></li>
    <li><a href="https://www.npmjs.com/package/@shakibdshy/signet-auth-client">npm: @shakibdshy/signet-auth-client</a></li>
    <li><a href="https://www.npmjs.com/package/@shakibdshy/signet-auth-react">npm: @shakibdshy/signet-auth-react</a></li>
  </ul>

  <footer>GET /healthz for uptime checks &middot; MIT licensed</footer>
</main>
</body>
</html>
`

// landingHandler serves the landing page at the root only; other unmatched
// paths keep the router's default 404.
func landingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(landingHTML))
}
