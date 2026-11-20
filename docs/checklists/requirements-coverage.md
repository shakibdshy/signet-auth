# Requirements coverage

Fill one file per phase at `docs/checklists/phase-N.md` **before** calling `code-review`. The published spec issue is the source of truth; this document only records the mapping.

Copy this template:

```md
# Requirements coverage — Phase N

Source: issue #N.

## Testing Decisions → tests

| Spec line (short quote) | Test or explained limitation |
| --- | --- |

## Security requirements → tests

| Requirement | Test or explained limitation |
| --- | --- |

## Cross-cutting sweep

- [ ] every rate-limited endpoint has a 429 test
- [ ] every exported sentinel has an errors.Is test
- [ ] every expiry branch is tested with the injected Clock
- [ ] no token, password, link or verifier appears in logs
- [ ] anti-enumeration paths do comparable work, or the gap is explained
- [ ] config defaults hold for a hand-built Config, not only DefaultConfig()
```

A row is done when it names a concrete test function or states a limitation a reviewer can accept. An empty cell means the phase is not ready for review.
