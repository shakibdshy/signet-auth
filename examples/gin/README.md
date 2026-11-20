# Gin example

A runnable Signet app using [Gin](https://github.com/gin-gonic/gin). Signet's
handler and protected handler are wrapped with `gin.WrapH`.

```sh
go run .
```

This is its own Go module with a `replace` to the repository root so Gin stays
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
