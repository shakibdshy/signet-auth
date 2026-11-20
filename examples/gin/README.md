# Gin example

A runnable Signet app using [Gin](https://github.com/gin-gonic/gin). Signet's
handler and protected handler are wrapped with `gin.WrapH`.

```sh
go run .
```

This is its own Go module with a `replace` to the repository root so Gin stays
out of the main module. The console mailer is for development only.
