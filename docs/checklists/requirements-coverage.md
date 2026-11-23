# Requirements coverage

Fill one file per phase at `docs/checklists/phase-N.md` **before** calling `code-review`. Cross-cutting work that is not a phase uses a descriptive name instead, such as `fuzz-testing.md`. The published spec issue is the source of truth; this document only records the mapping.

## Verification

Verify every row before review: grep each named test function and confirm it exists and asserts the behaviour the row claims. A ticked box without a matching test fails the checklist.

For every security mechanism the spec names, add one **effect test**: assert the observable result, not the mechanism's presence. A PKCE effect test asserts the provider received the verifier at exchange; a state effect test asserts a replayed callback is rejected; a CSRF effect test asserts a cross-site POST is blocked. Checking that `code_challenge=` appears in a URL proves the mechanism was constructed, not that it worked.

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

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |

## Cross-cutting sweep

- [ ] every rate-limited endpoint has a 429 test
- [ ] every exported sentinel has an errors.Is test
- [ ] every expiry branch is tested with the injected Clock
- [ ] no token, password, link or verifier appears in logs
- [ ] anti-enumeration paths do comparable work, or the gap is explained
- [ ] config defaults hold for a hand-built Config, not only DefaultConfig()
```

A row is done when it names a concrete test function or states a limitation a reviewer can accept. An empty cell means the phase is not ready for review.

## Phase checklists

Each shipped phase has a filled copy of this template, named for the phase rather than the generic `phase-N.md`:

- `foundation.md`
- `passwordless.md`
- `session-hardening.md`
- `phase3-sign-in-2fa.md`
- `phase4-oidc-provider.md`
- `phase6-defensive-controls.md`
