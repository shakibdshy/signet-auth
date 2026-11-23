# Requirements coverage — Phase 8a automatic sign-in

Source: issue #97; tickets #98–#100. Tests live in `tests/automatic_signin_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "disabled by default" | `TestAutomaticSignInDisabledByDefault`, `TestAutomaticSignInAfterVerificationDisabled` |
| "AfterVerification issues a Session" | `TestAutomaticSignInAfterVerification` |
| "verification Token stays single-use" | `TestAutomaticSignInAfterVerification` |
| "OnSignIn and sign_in_success with method email" | `TestAutomaticSignInAfterVerification`, `TestAutomaticSignInAfterSignUpWhenVerificationNotRequired` |
| "AfterSignUp issues a Session when verified or gate off" | `TestAutomaticSignInAfterSignUpWhenVerificationNotRequired` |
| "never bypass verification requirement" | `TestAutomaticSignInAfterSignUpBlockedForUnverified` |
| "HTTP cookies and session_token only when enabled" | `TestAutomaticSignInHTTPEndpoints` |
| "Last sign-in method records email" | `TestAutomaticSignInLastMethodCookie` |
| "rate-limit and captcha unchanged" | `TestAutomaticSignInDoesNotDuplicateRateLimit` |
| "source-compatible Go API" | `TestAutomaticSignInAfterVerificationDisabled` |

## Security requirements → tests

| Requirement | Test |
| --- | --- |
| Verification gate never bypassed | `TestAutomaticSignInAfterSignUpBlockedForUnverified` |
| Verification proof single-use | `TestAutomaticSignInAfterVerification` |
| Existing rate limits not duplicated | `TestAutomaticSignInDoesNotDuplicateRateLimit` |
| OnSignIn and Audit emitted consistently | `TestAutomaticSignInAfterVerification` |
| No surprise cookies when disabled | `TestAutomaticSignInDisabledByDefault`, `TestAutomaticSignInAfterVerificationDisabled` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Opt-in switches | no Session with switches off | `TestAutomaticSignInDisabledByDefault`, `TestAutomaticSignInAfterVerificationDisabled` |
| Single-use proof | replayed verification Token fails | `TestAutomaticSignInAfterVerification` |
| Verification gate | unverified User gets no Session | `TestAutomaticSignInAfterSignUpBlockedForUnverified` |
| Sign-in events | hook called once, audit has `method=email` | `TestAutomaticSignInAfterVerification` |
| Session validity | issued token resolves as a Session | `TestAutomaticSignInAfterVerification`, `TestAutomaticSignInAfterSignUpWhenVerificationNotRequired` |
| HTTP cookie policy | cookies only when a switch is on | `TestAutomaticSignInHTTPEndpoints` |
| Last sign-in method | cookie records `email` | `TestAutomaticSignInLastMethodCookie` |

## Cross-cutting sweep

- [x] every exported sentinel has an errors.Is test (none added)
- [x] generated artifacts and TS client rebuilt
- [x] backend code only in backend guides; frontend code only in frontend guide
- [x] no internal ADR references on public docs pages

## Accepted limitations

- The automatic sign-in config contains only boolean switches and a nil pointer disables the feature, so there is no invalid value for startup validation to reject.
