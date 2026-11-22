# Requirements coverage — Passwordless sign-in

Source: issues #54–#57. Design: `docs/superpowers/specs/2026-11-22-passwordless-sign-in-design.md`.

All tests named below live in `tests/passwordless_test.go` at the public `Client`/`Handler` seam.

## Testing Decisions → tests

| Spec line (short quote) | Test or explained limitation |
| --- | --- |
| "both magic link and email OTP in one phase" | `TestMagicLinkSignsInExistingUser`, `TestEmailOTPSignsInExistingUser` |
| "additional sign-in methods, never a replacement for passwords" | existing `tests/password_test.go` suite unchanged |
| "auto-create users on success, behind `AllowSignUp` (default true)" | `TestMagicLinkAutoCreatesVerifiedUser`, `TestEmailOTPAutoCreatesVerifiedUser`, `TestMagicLinkSendIsSilentWhenSignUpDisabled`, `TestEmailOTPSendIsSilentWhenSignUpDisabled` |
| "OTP is a Token with a new kind; six numeric digits; digest-only storage" | `TestEmailOTPSignsInExistingUser` |
| "a User with zero Accounts is valid" | `TestMagicLinkAutoCreatesVerifiedUser` |
| "one shared redirect-allowlist helper" | `TestMagicLinkRejectsOffOriginCallback`, existing OAuth callback tests |
| "optional template interfaces, no breaking change" | `TestDefaultPasswordlessTemplatesRenderBothBodies`; compile-time: custom `EmailTemplates` still satisfies the interface |
| "verification issues a Session immediately" | `TestMagicLinkHTTPFlowSetsCookie`, `TestEmailOTPHTTPFlowSetsCookie` |
| "OTP TTL 300 seconds; magic-link TTL 300 seconds" | `TestEmailOTPExpiresWithClock`, `TestMagicLinkExpiresWithClock`, `TestPasswordlessDefaultsHoldForHandBuiltConfig` |
| "3/min and 5/min are documented recommended rules" | `TestPasswordlessSendEndpointsAreRateLimited` asserts limiter consultation; exact windows documented in `passwordless.mdx` |
| "a proof sets `EmailVerified = true`" | `TestMagicLinkAutoCreatesVerifiedUser`, `TestEmailOTPAutoCreatesVerifiedUser` |
| "no password or Session revocation for existing users" | `TestMagicLinkSignsInExistingUser` (credential sign-in still available) |
| "one `PasswordlessConfig` pointer on `Config`" | `TestPasswordlessDefaultsHoldForHandBuiltConfig` |
| "a mismatched query callback is rejected" | `TestMagicLinkRejectsMismatchedCallbackAtVerification`, `TestMagicLinkRejectsUnlistedSameOriginCallback` |
| "New validates cfg" (negative passwordless TTL) | `TestPasswordlessConfigValidationRejectsNegativeTTL` |
| "with no callback, verification returns session JSON" | `TestMagicLinkHTTPFlowSetsCookie` |
| "resend rotates the proof" | `TestMagicLinkResendRotatesProof`, `TestEmailOTPReplayAndResendRotation` |
| "failed guesses throttled through the RateLimiter" | `TestEmailOTPFailedGuessesAreThrottled` |

## Security requirements → tests

| Requirement | Test or explained limitation |
| --- | --- |
| Raw OTP and magic-link token are never stored | `TestEmailOTPSignsInExistingUser`, `TestMagicLinkVerificationIsSingleUse` |
| Proofs are single-use and replay fails | `TestMagicLinkVerificationIsSingleUse`, `TestEmailOTPReplayAndResendRotation` |
| Resend invalidates the previous proof | `TestMagicLinkResendRotatesProof`, `TestEmailOTPReplayAndResendRotation` |
| Expired proofs are rejected | `TestMagicLinkExpiresWithClock`, `TestEmailOTPExpiresWithClock` |
| Off-origin redirects are rejected | `TestMagicLinkRejectsOffOriginCallback`, `TestMagicLinkRejectsUnlistedSameOriginCallback`, `TestMagicLinkRejectsMismatchedCallbackAtVerification` |
| Unknown emails do not disclose registration or enable mail relay | `TestMagicLinkSendIsSilentWhenSignUpDisabled`, `TestEmailOTPSendIsSilentWhenSignUpDisabled` |
| Standard and factor-specific sentinel errors reach callers | `TestPasswordlessErrorsUseStandardSentinels`, `TestConsumedTokenStillMatchesInvalidToken`, `TestIssueWithDataRoundTrip` (internal/token) |
| Wrong email and already-used OTP have distinct errors | `TestEmailOTPWrongEmailReturnsInvalidCode`, `TestEmailOTPConsumedCodeReportsAlreadyUsed`, `TestEmailOTPErrorWireCodes` |
| Malformed and already-used magic links have distinct errors | `TestMagicLinkReplayReportsAlreadyUsed`, `TestMagicLinkMalformedOrExpiredReportsInvalidLink`, `TestMagicLinkErrorWireCodes` |
| All four endpoints consult the limiter | `TestPasswordlessSendEndpointsAreRateLimited`, `TestPasswordlessVerifyEndpointsAreRateLimited` |
| No secrets in logs | `TestPasswordlessFlowsDoNotLogSecrets` |
| Anti-enumeration paths do comparable work | `TestMagicLinkSendIsSilentWhenSignUpDisabled`, `TestEmailOTPSendIsSilentWhenSignUpDisabled`; unknown path generates, digests and renders without sending. Limitation: transport time still differs without queued delivery |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Digest-only proof storage | stored Hash differs from the emailed code; replay fails | `TestEmailOTPSignsInExistingUser` |
| Atomic consume | second verification of the same proof fails | `TestEmailOTPReplayAndResendRotation`, `TestMagicLinkVerificationIsSingleUse` |
| Consumed OTP gets an actionable error | replay returns `code_already_used`, not a generic token error | `TestEmailOTPConsumedCodeReportsAlreadyUsed`, `TestEmailOTPErrorWireCodes` |
| Rotation | old proof/code rejected after resend | `TestMagicLinkResendRotatesProof`, `TestEmailOTPReplayAndResendRotation` |
| Redirect allowlist | off-origin callback rejected and no mail sent | `TestMagicLinkRejectsOffOriginCallback` |
| Rate limiter | 429 on all four HTTP endpoints; throttled wrong guesses | `TestPasswordlessSendEndpointsAreRateLimited`, `TestPasswordlessVerifyEndpointsAreRateLimited`, `TestEmailOTPFailedGuessesAreThrottled` |
| Injected Clock | proofs expire and valid-window behaviour holds | `TestEmailOTPExpiresWithClock`, `TestMagicLinkExpiresWithClock` |
| CSRF exemption for anonymous endpoints | GET/POST succeed without a CSRF token | `TestMagicLinkHTTPFlowSetsCookie`, `TestEmailOTPHTTPFlowSetsCookie` |

## Cross-cutting sweep

- [x] every rate-limited endpoint has a 429 test
- [x] every new exported sentinel has an errors.Is test (`TestPasswordlessErrorsUseStandardSentinels`, `TestMagicLinkReplayReportsAlreadyUsed`, `TestEmailOTPConsumedCodeReportsAlreadyUsed`, `TestConsumedTokenStillMatchesInvalidToken`)
- [x] every expiry branch is tested with the injected Clock
- [x] no token, password, link or verifier appears in logs
- [x] anti-enumeration paths do comparable work, or the gap is explained above
- [x] config defaults hold for a hand-built Config, not only DefaultConfig()
