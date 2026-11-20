# Requirements coverage — Phase 3

Source: issue #19.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| one seam, external `signet_test` package | all tests in `signet_test`, `console_test`, `smtp_test` |
| fake Mailer captures messages | `testutil.Mailer` in `internal/testutil/testutil.go` |
| console adapter writes to a buffer | `TestMailerWritesMessage` |
| SMTP adapter via construction validation | `TestNewValidatesConfiguration`, `TestNewAcceptsTLSModes` |
| sign-up auto-send and opt-out | `TestSignUpSendsVerificationEmail`, `TestSignUpKeepsUserWhenMailFails` |
| send/consume verification | `TestVerificationEndpoints`, `TestVerifyEmailMarksUserVerifiedAndIsSingleUse` |
| resend invalidation | `TestResendVerificationInvalidatesOldToken` |
| unverified sign-in gate | `TestUnverifiedSignInIsRejected`, `TestUnverifiedSignInHTTPIsForbidden` |
| send/consume reset | `TestResetEndpoints`, `TestResetPasswordChangesVerifierAndNotifies` |
| session and Token revocation after reset | `TestResetPasswordRevokesSessionsAndRejectsReplay` |
| post-reset notification | `TestResetPasswordChangesVerifierAndNotifies` |
| anti-enumeration unknown emails | `TestSendVerificationHidesUnknownEmail`, `TestSendPasswordResetHidesUnknownEmail` |
| rate limits | `TestVerificationSendRateLimited`, `TestVerificationConsumeRateLimited`, `TestPasswordResetSendRateLimited`, `TestPasswordResetConsumeRateLimited` |
| template rendering of both bodies | `TestDefaultTemplatesRenderBothBodies` |
| token expiry with injected Clock | `TestVerificationTokenExpiryUsesClock` |
| absence of secrets in logs | `TestPhase3FlowsDoNotLogSecrets` |
| password bounds | `TestResetPasswordEnforcesPasswordBounds` |

## Security requirements → tests

| Requirement | Test or limitation |
| --- | --- |
| Tokens random, single-use, short expiry | `newRawSecret` + `TestVerifyEmailMarksUserVerifiedAndIsSingleUse`, `TestVerificationTokenExpiryUsesClock` |
| Tokens stored hashed | `Token.Hash` asserted via `TestVerifyEmailMarksUserVerifiedAndIsSingleUse` |
| constant-time digest comparison | `subtle.ConstantTimeCompare` in `consumeToken`; exercised through all consume tests |
| reset invalidates all reset Tokens and Sessions | `TestResetPasswordRevokesSessionsAndRejectsReplay` |
| anti-enumeration with comparable work | unknown path generates a Token, digests it and renders the template; **limitation:** SMTP transport time still differs — equalizing needs queued delivery, out of scope for Phase 3 |
| rate limiting on all four endpoints | `TestVerificationSendRateLimited`, `TestVerificationConsumeRateLimited`, `TestPasswordResetSendRateLimited`, `TestPasswordResetConsumeRateLimited` |
| no secrets logged | `TestPhase3FlowsDoNotLogSecrets` |
| SMTP transport security | `TestNewValidatesConfiguration`, `TestNewAcceptsTLSModes` |
| secure defaults for hand-built Config | `TestConfigDefaultsApplyWithoutDefaultConfig` |

## Cross-cutting sweep

- [x] every rate-limited endpoint has a 429 test
- [x] every exported sentinel used by this phase has an errors.Is test
- [x] every expiry branch is tested with the injected Clock
- [x] no token, password, link or verifier appears in logs
- [x] anti-enumeration gap explained above
- [x] config defaults hold for a hand-built Config
