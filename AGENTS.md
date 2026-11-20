## Agent skills

### Issue tracker

Issues and specs live in GitHub Issues for shakibdshy/signet, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Triage uses the five canonical role labels (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: one `GLOSSARY.md` at the repo root and ADRs in `docs/adr/`. See `docs/agents/domain.md`.

## Requirements coverage

Before calling code-review, fill in and verify `docs/checklists/phase-N.md` from `docs/checklists/requirements-coverage.md`: every row must name an existing test, and every security mechanism needs an effect test asserting its observable result.
