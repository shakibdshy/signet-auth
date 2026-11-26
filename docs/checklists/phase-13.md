# Requirements coverage — Phase 13 session client info, richer /me, canonical sign-in method

Source: #145 (tickets #146–#152). Tests live in `tests/session_user_agent_test.go`,
`tests/session_user_agent_flows_test.go`, `tests/me_profile_test.go`,
`tests/sign_in_method_test.go`, `tests/last_method_test.go`, `store/postgres/migration_test.go`
and `store/sqlite/migration_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "Sessions record the sign-in client" | `TestSignInRecordsUserAgentOnSession`, `TestMagicLinkVerificationRecordsUserAgent`, `TestEmailOTPVerificationRecordsUserAgent`, `TestSignUpAutoSignInRecordsUserAgent`, `TestVerificationAutoSignInRecordsUserAgent`, `TestOAuthCallbackRecordsUserAgent`, `TestSSOCallbackRecordsUserAgent`, `TestSAMLACSRecordsUserAgent`, `TestPasskeyFinishRecordsUserAgent`, `TestVerifyTwoFactorRecordsUserAgent`, `TestImpersonationRecordsUserAgent`, `TestTokenPasswordGrantRecordsUserAgent` |
| "empty string when absent" | `TestSignInRecordsEmptyUserAgentWhenHeaderAbsent`, `TestProgrammaticSignInRecordsEmptyUserAgent` |
| "truncated to a sane cap" | `TestUserAgentTruncatedToRuneBoundary` |
| "migrations idempotent; old rows read \"\"" | `TestMigrateUpgradesBetaSchema` (both adapters, run twice against the 1.0.0-beta schema) |
| "custom Stores persist the field" | `conformance.testSessions` round-trip + `TouchSession` non-disturbance |
| "GET /me returns the full User" | `TestMeReturnsUsernameVerificationAndTimestamps` |
| "username empty when none, never an error" | `TestMeUsernameIsEmptyForEmailOnlyUser` |
| "email_verified reflects verification" | `TestMeEmailVerifiedTrueAfterVerification` |
| "canonical method values" | `TestPasswordSignInReportsMethodInBodyAndCookie`, `TestUsernameSignInReportsPassword`, `TestMagicLinkSignInReportsCanonicalMethod`, `TestEmailOTPSignInReportsCanonicalMethod`, `TestSignUpAutoSignInReportsBackingFactor`, `TestVerificationAutoSignInReportsMagicLink`, `TestOAuthCallbackRecordsGenericMethod`, `TestSSOCallbackReportsMethod`, `TestSAMLACSReportsMethod` |
| "cookie written only once a Session is issued" | `TestTwoFactorChallengeWritesNoCookie` |
| "body field independent of the cookie feature" | `TestSignInReportsMethodWhenFeatureDisabled` |
| "spec-only contract fixes" | `TestGenerateSignUpResponseUsesLowercaseUserKey`, `TestGenerateSignInInputEmailOptional` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Handler-derived UserAgent is not client-forgeable input | `UserAgent` fields are `json:"-"`, absent from the generated spec and never decoded from a body | `TestGenerateSignUpResponseUsesLowercaseUserKey` companions: generated `SignInInput`/`TokenInput` schemas expose no `user_agent` (covered by generator skip of `json:"-"`, asserted via `TestGenerateOpenAPIDocument` rate_limit_key exclusion pattern) |
| Truncation bounds stored size and validity | 800-rune multibyte header stored as exactly 512 runes, valid UTF-8, prefix of the original | `TestUserAgentTruncatedToRuneBoundary` |
| Tampered last-method cookie is ignored | tampered value reads as `""` | `TestLastMethodRejectsTamperedCookie` |
| Consent gate still suppresses the cookie | `BeforeStore` false: Go result keeps the method, no cookie over HTTP | `TestLastMethodGoResultAndConsent` |
| Opt-in stays opt-in | feature disabled: bodies still carry the method, no cookie written, read returns `""` | `TestSignInReportsMethodWhenFeatureDisabled` |
| A challenge is not a sign-in | challenge response writes no cookie; previous value preserved | `TestTwoFactorChallengeWritesNoCookie` |
| Store migration is replay-safe | beta schema upgraded twice-run; pre-existing rows read `""` | `TestMigrateUpgradesBetaSchema` (Postgres + SQLite) |

## Cross-cutting sweep

- [x] generated artifacts and TS client rebuilt (`make generate-check` green)
- [x] no `user_agent` or `last_sign_in_method` accepted from request bodies (all `json:"-"` or handler-set)
- [x] no token, password or verifier stored in the new column (raw header only, capped at 512 runes)
- [x] backend docs updated where the shapes are documented (sessions, storage, defensive-controls, frontend-client, http-api endpoint table)
- [x] no internal ADR references on public docs pages; the decision is recorded as ADR-0014 in `docs/adr/`
- [x] config defaults hold for a hand-built Config: the cookie stays nil (disabled) unless configured; bodies report the method regardless
