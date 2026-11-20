# Chi example

A runnable Signet app using [Chi](https://github.com/go-chi/chi/v5). Signet's
handler is mounted with `Mount`, and `RequireAuth` is applied with `With`.

```sh
go run .
```

This is its own Go module with a `replace` to the repository root so Chi stays
out of the main module. The console mailer is for development only.

## PostgreSQL

This example uses the bundled PostgreSQL adapter. Start a local database with
OrbStack/Docker:

```sh
docker run -d --name signet-postgres \
  -e POSTGRES_USER=signet -e POSTGRES_PASSWORD=signet -e POSTGRES_DB=signet \
  -p 5432:5432 postgres:16-alpine
```

The app connects to `postgres://signet:signet@localhost:5432/signet?sslmode=disable`
by default. Override it with `SIGNET_DATABASE_URL`. Migrations are applied
explicitly at startup with `store.Migrate(ctx)`.
