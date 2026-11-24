# Requirements coverage — Phase 12 React session hooks

Source: issue #125. Tests live in `tests/me_test.go`; TypeScript surface is checked by `client/react/src/type-contracts.ts`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "GET /me returns safe User fields" | `TestMeEndpoint` |
| "auth-only" | `TestMeEndpointRequiresSession` |
| "typed React package surface" | `client/react` typecheck + type-contracts |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Authentication | anonymous `/me` denied | `TestMeEndpointRequiresSession` |
| Safe fields | no verifier or secret in response | `TestMeEndpoint` |

## Cross-cutting sweep

- [x] generated client rebuilt with `me()`
- [x] React package builds and typechecks locally
- [x] frontend docs updated; stale `/session` read guidance corrected
- [x] no ADR references on public docs pages
