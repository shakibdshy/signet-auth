# Requirements coverage — fuzz testing

Source: issue #40.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| Argon2 verifier parsing | `FuzzArgonVerifier` |
| Session token handling | `FuzzSessionTokenSignOut` |
| JSON request bodies | `FuzzJSONRequestBodies` |
| OAuth state | `FuzzOAuthState` |
| CSRF token validation | `FuzzCSRFToken` |
| external seam only | **limitation:** cross-cutting property verified by review; all targets are in `signet_test` |
| no production API changes | **limitation:** cross-cutting property verified by review; no exported test hooks added |

## Security requirements → tests

| Requirement | Test |
| --- | --- |
| no panic on untrusted input | all five `Fuzz*` targets |
| malformed verifiers, state and tokens rejected | `FuzzArgonVerifier`, `FuzzOAuthState`, `FuzzCSRFToken` |
| arbitrary JSON never produces a server error | `FuzzJSONRequestBodies` |
| single-use Session tokens cannot be guessed | `FuzzSessionTokenSignOut` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| malformed verifier parsing | no panic and malformed PHC strings rejected | `FuzzArgonVerifier` |
| arbitrary Session token | SignOut never panics or errors | `FuzzSessionTokenSignOut` |
| arbitrary JSON body | HTTP status stays below 500 | `FuzzJSONRequestBodies` |
| malformed OAuth state | only ErrOAuthInvalidState is returned | `FuzzOAuthState` |
| malformed CSRF token | only 403 or 204 is returned with a valid CSRF cookie present | `FuzzCSRFToken` |

## Cross-cutting sweep

- [x] every parser named in the spec has a target
- [x] every target lives in the external test package
- [x] make fuzz runs all targets with a bounded duration
- [x] CI runs fuzzing on one matrix job only
- [x] no fuzzing of third-party dependency internals
