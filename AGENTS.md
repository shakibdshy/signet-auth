## Agent skills

### Issue tracker

Issues and specs live in GitHub Issues for shakibdshy/signet, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Triage uses the five canonical role labels (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: one `GLOSSARY.md` at the repo root and ADRs in `docs/adr/`. See `docs/agents/domain.md`.

## Code layout

The root `signet` package is a five-file façade (`signet.go`, `client.go`,
`config.go`, `errors.go`, `doc.go`): exported names are aliases of private types
in `internal/` (`core` holds the shared domain types, `auth`, `session`, `token`,
`oauth`, `csrf`, `mail`, `secret`, `httpapi` hold implementations), and root
methods delegate to those packages. Put new behaviour in the appropriate
`internal/` package and expose it through root aliases or delegation. Black-box
tests of the public API live in `tests/`. Production packages under `internal/`
must not import the root package — that would create an import cycle. The sole
exception is the test-only `internal/testutil`. See
`docs/adr/0002-public-api-in-root-package.md`.

## Requirements coverage

Before calling code-review, fill in and verify `docs/checklists/phase-N.md` from `docs/checklists/requirements-coverage.md`: every row must name an existing test, and every security mechanism needs an effect test asserting its observable result.
