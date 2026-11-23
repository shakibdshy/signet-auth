# Requirements coverage — Phase 10 SCIM provisioning

Source: accepted design decisions from the enterprise identity plan. Tests live in `tests/scim_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "SCIM disabled by default" | `TestSCIMDisabledAndUnauthorized` |
| "bearer token compared in constant time" | `TestSCIMDisabledAndUnauthorized` |
| "config validated at startup" | `TestSCIMConfigValidation` |
| "Users create/list/patch" | `TestSCIMUserLifecycle` |
| "Group projection callback" | `TestSCIMGroupProjection` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Opt-in | disabled SCIM returns 404 | `TestSCIMDisabledAndUnauthorized` |
| Authentication | missing/wrong token returns 401 | `TestSCIMDisabledAndUnauthorized` |
| Config validation | missing store or token rejected | `TestSCIMConfigValidation` |
| External identity mapping | externalId stored and resolvable | `TestSCIMUserLifecycle` |
| Group projection | projector called with group members | `TestSCIMGroupProjection` |

## Cross-cutting sweep

- [x] generated artifacts and typed client rebuilt
- [x] backend code only in backend guides
- [x] no internal ADR references on public docs pages
