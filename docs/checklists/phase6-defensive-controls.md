# Requirements coverage — Phase 6 defensive controls

Source: issues #71–#75. Design: `docs/superpowers/specs/2026-11-23-defensive-controls-design.md`. ADR-0011 records the opt-in interface decision. i18n and anomaly detection are fully out of scope.

Tests live in `tests/breach_test.go`, `tests/captcha_test.go`, `tests/audit_test.go` and `tests/last_method_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "blocking, opt-in breach check" | `TestBreachCheckBlocksSignUp`, `TestBreachCheckBlocksPasswordChange`, `TestBreachCheckBlocksPasswordReset` |
| "provider errors fail closed" | `TestBreachProviderFailureFailsClosed` |
| "captcha accepts and rejects tokens" | `TestCaptchaAcceptsAndRejectsSignUp`, `TestCaptchaProviderFailureRejected` |
| "missing token rejected" | `TestCaptchaMissingTokenRejected` |
| "endpoint list is configurable" | `TestCaptchaEndpointSelection` |
| "after rate limiting" | `TestCaptchaRunsAfterRateLimit` |
| "X-Captcha-Response and trusted client IP" | `TestCaptchaHTTPUsesHeaderAndClientIP` |
| "audit sink receives security events" | `TestAuditSinkReceivesSecurityEvents` |
| "no secrets in audit metadata" | `TestAuditEventsContainNoSecrets` |
| "sink failure never fails the request" | `TestAuditSinkFailureDoesNotBreakAuthentication` |
| "signed HttpOnly cookie on successful sign-in" | `TestLastMethodSetByHTTPSignIn` |
| "consent can skip storing without failing sign-in" | `TestLastMethodGoResultAndConsent` |
| "tampered cookie treated as absent" | `TestLastMethodRejectsTamperedCookie` |
| "clear and expire" | `TestLastMethodClear`, `TestLastMethodExpires` |
| "requires CSRF keys" | `TestLastMethodRequiresCSRFKeys` |

## Security requirements → tests

| Requirement | Test or explained limitation |
| --- | --- |
| A breached password is never accepted | three `TestBreachCheckBlocks*` effect tests |
| Breach provider failure cannot silently pass | `TestBreachProviderFailureFailsClosed` |
| Captcha cannot be bypassed by a Go caller | `TestCaptchaAcceptsAndRejectsSignUp`, `TestCaptchaEndpointSelection` |
| Captcha cannot hammer the provider before rate limiting | `TestCaptchaRunsAfterRateLimit` |
| Audit events contain no credentials or tokens | `TestAuditEventsContainNoSecrets` |
| Optional controls never break authentication | `TestAuditSinkFailureDoesNotBreakAuthentication`, `TestLastMethodGoResultAndConsent` |
| Last method cannot be forged by the client | `TestLastMethodRejectsTamperedCookie` |
| No new schema or required Config field | limitation verified by design: all new fields are pointers/interfaces and optional |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Breach check | dedicated 400 error and no credential change | `TestBreachCheckBlocks*` |
| Fail-closed provider | request rejected with a provider error | `TestBreachProviderFailureFailsClosed` |
| Captcha header + IP | verifier receives the header value and a client IP | `TestCaptchaHTTPUsesHeaderAndClientIP` |
| Rate-limit ordering | provider not called when the limiter denies | `TestCaptchaRunsAfterRateLimit` |
| Audit projection | security event names delivered to the sink | `TestAuditSinkReceivesSecurityEvents` |
| Audit metadata safety | no password or Session token in metadata | `TestAuditEventsContainNoSecrets` |
| Signed method cookie | tampered value returns an empty method | `TestLastMethodRejectsTamperedCookie` |
| Consent gate | no cookie written when consent is false; sign-in succeeds | `TestLastMethodGoResultAndConsent` |

## Cross-cutting sweep

- [x] every opt-in control has a disabled-by-default path tested elsewhere in the suite
- [x] every new exported sentinel has an errors.Is test
- [x] no secret, verifier or token appears in Audit events
- [x] failure isolation tested for Audit sink and consent callback
- [x] status and research pages state that i18n is fully out of scope
