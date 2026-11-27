# Architecture notes

## Code layout

The root `signet` package is a five-file façade (`signet.go`, `client.go`,
`config.go`, `errors.go`, `doc.go`): exported names are aliases of private types
in `internal/` (`core` holds the shared domain types, `auth`, `session`, `token`,
`oauth`, `csrf`, `mail`, `secret`, `httpapi` hold implementations), and root
methods delegate to those packages. Put new behaviour in the appropriate
`internal/` package and expose it through root aliases or delegation. Black-box
tests of the public API live in `tests/`. Production packages under `internal/`
must not import the root package — that would create an import cycle. The sole
exception is the test-only `internal/testutil`.
