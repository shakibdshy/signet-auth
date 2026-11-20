# Echo example

A runnable Signet app using [Echo](https://echo.labstack.com/). Signet's handler
is wrapped with `echo.WrapHandler`, and the middleware with
`echo.WrapMiddleware`.

```sh
go run .
```

This is its own Go module with a `replace` to the repository root so Echo stays
out of the main module. The console mailer is for development only.
