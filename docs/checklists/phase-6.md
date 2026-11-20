# Requirements coverage — Phase 6

Source: issue #35.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| one behavioural seam via public API | all CSRF tests use `signet_test` with `httptest` |
| CSRF token issued on sign-in and /csrf-token | `TestCSRFTokenInSignInResponse`, `TestCSRFAllowsSameOriginWithToken` |
| valid token accepted, missing/tampered/expired rejected | `TestCSRFAllowsSameOriginWithToken`, `TestCSRFRejectsMissingAndTamperedTokens`, `TestCSRFTokenExpires` |
| anonymous endpoints exempt | `TestCSRFDoesNotAffectAnonymousRequests` |
| origin checks still enforced | `TestCSRFRejectsCrossOriginStateChange`, `TestCSRFRejectsCrossSiteFetch` |
| opt-out logs a warning | `TestCSRFCanBeDisabledExplicitly` |
| missing key rejected, JWT-only exempt | `TestNewRequiresCSRFKeyForCookieSessions`, `TestJWTOnlyDoesNotRequireCSRFKey` |
| protected application handlers checked | `TestCSRFGuardCoversProtectedApplicationHandlers` |
| examples compile | `make examples` (build verification, not a Go test) |
| documentation reviewed | **limitation:** docs are review-only, not executable behaviour; no test applies |

## Security requirements → tests

| Requirement | Test or explained limitation |
| --- | --- |
| signed token cannot be forged | `TestCSRFRejectsMissingAndTamperedTokens` |
| token expiry with injected Clock | `TestCSRFTokenExpires` |
| session cookie stays HttpOnly | `TestSignInSetsSecureHostCookie` |
| no token in logs | `TestCSRFDoesNotLogTokens` |
| CSRF failure emits event | `TestCSRFRejectionEventHasNoToken` asserts the event and absence of the token |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| signed double-submit | valid token reaches handler; tampered token is blocked | `TestCSRFAllowsSameOriginWithToken`, `TestCSRFRejectsMissingAndTamperedTokens` |
| token rotation | old token plus refreshed cookie is rejected | `TestOldCSRFTokenCannotBeReplayedAfterRefresh` |
| token expiry | expired token blocked after Clock advance | `TestCSRFTokenExpires` |
| origin and fetch-site checks | cross-site requests blocked even with a valid token | `TestCSRFRejectsCrossOriginStateChange`, `TestCSRFRejectsCrossSiteFetch` |
| CSRF key requirement | construction fails without a 32-byte key | `TestNewRequiresCSRFKeyForCookieSessions` |
| router independence | four example modules build against `net/http` wrappers | `make examples` |

## Cross-cutting sweep

- [x] every CSRF endpoint and rejection path has a test
- [x] all new sentinels have errors.Is tests
- [x] expiry asserted with the injected Clock
- [x] no token, cookie or secret appears in logs
- [x] existing session-cookie tests updated for the second cookie
- [x] examples build in CI
