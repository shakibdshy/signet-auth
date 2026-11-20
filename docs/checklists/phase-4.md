# Requirements coverage — Phase 4

Source: issue #24.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| one seam, external `signet_test` package | all root tests use `signet_test` |
| fake provider and stubbed token endpoint | `fakeOAuthProvider` in `tests/oauth_provider_test.go`; `httptest` servers in `oauth/google/google_test.go` and `oauth/github/github_test.go` |
| root package plus adapter packages | `tests/oauth_provider_test.go`, `tests/oauth_security_test.go`, `tests/oauth_start_test.go`, `tests/oauth_callback_test.go`, adapter tests |
| OAuth disabled by default | `TestOAuthDisabledByDefault` |
| unknown provider and disallowed redirect | `TestOAuthStartValidatesRequest` |
| state tampering and expiry | `TestOAuthCallbackRejectsTamperedState`, `TestOAuthStateExpires` |
| PKCE challenge in authorization URL | `TestOAuthStartReturnsPKCEAndState`, `TestPKCEVerifierIsNotExposedInURL` |
| PKCE verifier presented at token endpoint | `TestPKCEVerifierReachesProvider` |
| single-use state | `TestOAuthStateIsSingleUse` |
| link token expiry | `TestLinkTokenExpires` |
| OAuth sentinels | `TestOAuthEmailNotVerifiedSentinel`, `TestOAuthAccountConflictSentinel` |
| verified-email auto-link and new User | `TestOAuthCallbackAutoLinksExistingUser`, `TestOAuthCallbackCreatesUserWithVerifiedEmail` |
| unverified-email explicit linking | `TestOAuthCallbackRequiresExplicitLinkForUnverifiedEmail` |
| Session creation and cookie on callback | `TestOAuthCallbackCreatesUserWithVerifiedEmail`, `TestOAuthCallbackHTTPRedirectsWithSession` |
| rate limits | `TestOAuthStartRateLimited`, `TestOAuthCallbackRateLimited` |
| no secrets in logs | `TestOAuthDoesNotLogSecrets` |
| Google and GitHub identity mapping | `TestProviderImplementsContractAndMapsIdentity`, `TestProviderImplementsContractAndMapsVerifiedEmail`, `TestProviderTreatsUnverifiedEmailAsUnverified` |

## Security requirements → tests

| Requirement | Test or limitation |
| --- | --- |
| Authorization Code with state and PKCE | `TestOAuthStartReturnsPKCEAndState`, `TestOAuthCallbackRejectsTamperedState` |
| state encrypted and tamper-proof | AES-GCM in `sealValue`/`openValue`, exercised by `TestPKCEVerifierIsNotExposedInURL` and the tamper test |
| redirect allowlist | `TestOAuthStartValidatesRequest`; callback rechecks state redirect |
| auto-link only when email verified | `TestOAuthCallbackAutoLinksExistingUser`, `TestOAuthCallbackRequiresExplicitLinkForUnverifiedEmail` |
| link token single-use | `TestOAuthCallbackRequiresExplicitLinkForUnverifiedEmail` |
| rate limiting on start and callback | `TestOAuthStartRateLimited`, `TestOAuthCallbackRateLimited` |
| no state, code, verifier or token logged | `TestOAuthDoesNotLogSecrets` |
| vetted OAuth dependency | `golang.org/x/oauth2` used in both adapters |
| authorization code replay | **limitation:** enforcement belongs to the provider; Signet consumes state once (`TestOAuthStateIsSingleUse`) but does not store authorization codes |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| PKCE | provider receives the verifier at exchange | `TestPKCEVerifierReachesProvider` |
| encrypted state | tampered state is rejected | `TestOAuthCallbackRejectsTamperedState` |
| single-use state | replayed callback is rejected | `TestOAuthStateIsSingleUse` |
| verifier confidentiality | verifier absent from the authorization URL | `TestPKCEVerifierIsNotExposedInURL` |
| verified-only auto-link | unverified email creates no User | `TestOAuthCallbackRequiresExplicitLinkForUnverifiedEmail` |
| single-use link token | replayed link token fails | `TestOAuthCallbackRequiresExplicitLinkForUnverifiedEmail` |
| rate limiting | 429 from start and callback | `TestOAuthStartRateLimited`, `TestOAuthCallbackRateLimited` |

## Cross-cutting sweep

- [x] every rate-limited endpoint has a 429 test
- [x] every exported sentinel used by this phase has an errors.Is test
- [x] expiry branch tested with the injected Clock
- [x] no state, code, verifier or token appears in logs
- [x] anti-enumeration not applicable to OAuth callbacks
- [x] config defaults hold for a hand-built Config
