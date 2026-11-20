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
