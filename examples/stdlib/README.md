# Standard library example

A runnable Signet app with no framework at all: Go's `http.ServeMux` routes, Signet's
handler mounted at `/auth`, and one protected route. Use this example to see the smallest
possible Signet integration; the chi, echo, gin and fiber examples show the same app on
popular routers.

## Run it

Start PostgreSQL (or point `SIGNET_DATABASE_URL` at a database you already have):

```sh
docker run -d --name signet-postgres \
  -e POSTGRES_USER=signet -e POSTGRES_PASSWORD=signet -e POSTGRES_DB=signet \
  -p 5432:5432 postgres:16-alpine
```

Then:

```sh
go run .
```

Migrations are applied at startup with `store.Migrate(ctx)` and `orgStore.Migrate(ctx)`;
the latter creates the example's organization and membership tables.

### Environment

| Variable | Purpose | Default |
| --- | --- | --- |
| `SIGNET_DATABASE_URL` | PostgreSQL connection string | local DSN on `localhost:5432` |
| `PORT` | listen port (hosts like Render inject it) | `8080` |
| `APP_URL` | public origin used in verification and reset links | `http://localhost:PORT` |
| `CSRF_KEY` | persistent base64 CSRF key, `openssl rand -base64 32` | random per boot (development only) |

## Walk the full flow

With the app running, follow along with curl (needs [jq](https://jqlang.github.io/jq/)).
Step 3 matters: sign-in rotates the CSRF token, and every later state-changing call must
use the one from the sign-in response — that is also what the typed TypeScript client does
for you.

```sh
# 1. Get a CSRF token; the call also sets a cookie into jar.txt.
TOKEN=$(curl -s -c jar.txt http://localhost:8080/auth/csrf-token | jq -r .token)

# 2. Sign up. name is required.
curl -s -b jar.txt -c jar.txt -H "X-CSRF-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple","name":"Ada"}' \
  http://localhost:8080/auth/signup
# → 201 and the User as JSON

# 3. Sign in; the Session cookie lands in jar.txt, and the response
#    carries the fresh csrf_token used by the next steps.
RESP=$(curl -s -b jar.txt -c jar.txt -H "X-CSRF-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple"}' \
  http://localhost:8080/auth/signin)
TOKEN=$(echo "$RESP" | jq -r .csrf_token)

# 4. Call the protected route with the Session cookie.
curl -s -b jar.txt http://localhost:8080/private
# → hello ada@example.com

# 5. Sign out (204, empty body) — with the fresh token, not the original one.
curl -s -b jar.txt -c jar.txt -H "X-CSRF-Token: $TOKEN" \
  -H 'Content-Type: application/json' -d '{}' \
  -o /dev/null -w '%{http_code}\n' http://localhost:8080/auth/signout
# → 204

# 6. The Session is revoked.
curl -s -o /dev/null -w '%{http_code}\n' -b jar.txt http://localhost:8080/private
# → 401
```

Sign-up again after step 2 with the same email? Use a new address, or expect `email_exists`.

## Self-serve organizations

Any authenticated user can create an organization and manage its members:

```sh
# Create an organization — the creator is stored as its owner.
ORG=$(curl -s -b jar.txt -c jar.txt -H "X-CSRF-Token: $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"Acme"}' \
  http://localhost:8080/auth/organizations)
ORG_ID=$(echo "$ORG" | jq -r .Organization.id)
curl -s -b jar.txt http://localhost:8080/auth/organizations

# Add, promote and remove a member (owner/admin only).
curl -s -b jar.txt -c jar.txt -H "X-CSRF-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"organization_id\":\"$ORG_ID\",\"user_id\":\"member-1\",\"role\":\"member\"}" \
  http://localhost:8080/auth/organization-members/add
curl -s -b jar.txt -c jar.txt -H "X-CSRF-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"organization_id\":\"$ORG_ID\",\"user_id\":\"member-1\",\"role\":\"admin\"}" \
  http://localhost:8080/auth/organization-members/role
curl -s -b jar.txt -c jar.txt -H "X-CSRF-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"organization_id\":\"$ORG_ID\",\"user_id\":\"member-1\"}" \
  http://localhost:8080/auth/organization-members/remove
```

This is example configuration, not a Signet default. The authorizer grants only
`organizations:create` (`signet.PermissionOrgsCreate`) to the ordinary `user` role, so
the admin/system routes stay disabled. The `AuthorizeIn` callback re-reads membership on
every org-scoped check and allows `organizations:member-add`, `member-remove` and
`member-role` only for members whose organization role is `owner` or `admin`; plain
members and non-members get `403`. Every mutation still needs a fresh session and a
valid CSRF token.

## How Signet is wired in

```go
mux.HandleFunc("GET /{$}", landingHandler)
mux.Handle("/auth/", auth.Handler())
mux.Handle("/private", auth.RequireAuth(http.HandlerFunc(...)))
```

The root path serves a small landing page describing the service and its
endpoints, and `GET /healthz` is the uptime probe for platform health checks.

`auth.Handler()` serves the full `/auth/...` paths itself — **do not** wrap it in
`http.StripPrefix`; a stripped prefix makes every auth call return 404.
`auth.RequireAuth` is a plain `net/http` middleware: it loads the Session from the
request's cookie and puts the User into the request context, where
`signet.UserFromContext(r.Context())` reads it.

## Development-only settings

Two lines skip email verification so the flow above works without a mailbox:

```go
no := false
cfg.RequireVerifiedEmail = &no
cfg.SendVerificationOnSignUp = &no
```

Leave them unset (or true) in production. Without them, sign-in answers `email_not_verified`
until the User opens the verification link that the console mailer prints to stdout.

The console mailer and the in-memory rate limiter are for development only. This example
is its own Go module with a `replace` to the repository root, so the framework
dependencies stay out of the main module.
