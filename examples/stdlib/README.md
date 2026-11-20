# Standard library example

A runnable Signet app using only `net/http`. It migrates a SQLite database,
exposes Signet's endpoints under `/auth/`, and protects `/private` with
`RequireAuth`.

```sh
go run .
```

This is its own Go module with a `replace` to the repository root so framework
dependencies stay out of the main module. The console mailer is for development
only — it prints verification and reset links to stdout.

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
