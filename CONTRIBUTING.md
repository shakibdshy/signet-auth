# Contributing to Signet

Thanks for your interest in improving Signet. The project is early in its life,
so contributions of all sizes are welcome: bug reports, documentation, tests,
and code.

## Development setup

You will need a supported Go release (see the `go` directive in `go.mod`) and the
following developer tools:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install golang.org/x/tools/cmd/goimports@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```

Make sure `$(go env GOPATH)/bin` is on your `PATH`; the Makefile adds it itself,
but direct invocations of the tools need it.

## Running checks

```sh
make test    # go test -race ./...
make vet     # go vet ./...
make lint    # golangci-lint run ./...
make vuln    # govulncheck ./...
make cover   # race-enabled tests plus a coverage report
make check   # formatting, vet, lint, tests, and vulnerability scan
```

Please run `make check` before opening a pull request.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add session store interface
fix: reject expired tokens
docs: document the mailer interface
chore: bump CI actions
```

Common types are `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, and
`perf`.

## Pull requests

- **Every PR must include tests.** New behaviour needs new test coverage; bug
  fixes need a regression test that fails before the fix.
- Keep changes focused and explain the motivation in the description.
- Update documentation when behaviour or the public API changes.
- Make sure CI is green and `make check` passes locally.
