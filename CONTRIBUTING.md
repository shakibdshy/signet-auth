# Contributing to Signet

Thanks for your interest in improving Signet. The project is early in its life,
so contributions of all sizes are welcome: bug reports, documentation, tests,
and code.

## Development setup

You will need a supported Go release (see the `go` directive in `go.mod`) and
Node.js with npm for the TypeScript client, React package and docs site. Install
the Go developer tools:

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
make check       # fmt, vet, lint, race tests, vuln, TS typechecks, docs guard + build
```

Other useful targets: `make generate-check` verifies generated OpenAPI/TS artifacts,
`make docs-site` runs the docs guard and build, and `make ts-check` typechecks both
TypeScript packages. Please run `make check` before opening a pull request.

When changing an HTTP request or response shape, update the declarative
contract in `internal/httpapi/contract.go` and run `make generate`. CI runs
`make generate-check`, which fails if the committed OpenAPI spec or generated
TypeScript types are stale. Shape changes are breaking changes for the
published client and require a major version bump; adding a response field is
the additive case and needs only a minor-level bump, while renaming or
removing a field is the breaking case.

## Code review with OCR

The repository ships a project-local OpenCodeReview plugin under `.opencode/`,
so these tools are available after restarting OpenCode in this checkout:

- `/ocr-review` reviews code. Examples: "review current workspace",
  "compare main to HEAD", or "review current changes; focus on auth regressions".
- `/ocr-health` checks the installed OCR version and its configured model.

Credentials stay in the OCR CLI configuration or environment, never in git.

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
- Complete the requirements coverage checklist for the phase before review.
  Every Testing Decisions line and security requirement must name a test or an
  explained limitation; see `docs/checklists/requirements-coverage.md` and the
  phase files it indexes (`phase5-authorization.md`, `phase-7.md` … `phase-12.md`).
- Keep changes focused and explain the motivation in the description.
- Update documentation when behaviour or the public API changes.
- Make sure CI is green and `make check` passes locally.
