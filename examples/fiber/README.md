# Fiber example

A runnable Signet app using [Fiber](https://gofiber.io/). Fiber runs on
`fasthttp`, not `net/http`, so Signet's handlers and middleware are bridged with
Fiber's official `middleware/adaptor` package:

- `adaptor.HTTPHandler` mounts Signet's auth endpoints.
- `adaptor.HTTPMiddleware` applies `RequireAuth` to a protected route.

```sh
go run .
```

This is its own Go module with a `replace` to the repository root so Fiber stays
out of the main module. The console mailer is for development only.

## PostgreSQL

Start a local database with OrbStack/Docker:

```sh
docker run -d --name signet-postgres \
  -e POSTGRES_USER=signet -e POSTGRES_PASSWORD=signet -e POSTGRES_DB=signet \
  -p 5432:5432 postgres:16-alpine
```

The app connects to `postgres://signet:signet@localhost:5432/signet?sslmode=disable`
by default. Override it with `SIGNET_DATABASE_URL`. Migrations are applied
explicitly at startup with `store.Migrate(ctx)`.
