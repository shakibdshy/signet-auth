# Chi example

A runnable Signet app using [Chi](https://github.com/go-chi/chi/v5). Signet's
handler is mounted with `Mount`, and `RequireAuth` is applied with `With`.

```sh
go run .
```

This is its own Go module with a `replace` to the repository root so Chi stays
out of the main module. The console mailer is for development only.
