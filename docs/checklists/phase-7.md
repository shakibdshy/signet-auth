# Requirements coverage — Phase 7 passkeys

Source: issue #90; tickets #91–#95. Tests live in `tests/passkey_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "enroll a discoverable Passkey" | `TestPasskeyEnrollmentAndListing`, `TestPasskeyHTTPEndpoints` |
| "registration ceremony state in single-use Token kinds" | `TestPasskeyRegistrationReplayRejected`, `TestPasskeyCeremonyExpiry` |
| "enrollment requires fresh Session and verified email" | `TestPasskeyEnrollmentRequiresFreshSession`, `TestPasskeyEnrollmentRequiresVerifiedEmail`, `TestPasskeyRegistrationBindsSessionUser` |
| "sign in without a username" | `TestPasskeySignInCreatesSession`, `TestPasskeyHTTPEndpoints` |
| "records passkey as Last sign-in method" | `TestPasskeySignInRecordsLastMethod` |
| "replayed assertion rejected" | `TestPasskeySignInReplayRejected` |
| "sign count stored and regression audited" | `TestPasskeySignCountRegressionAudit` |
| "list and delete passkeys, owner-scoped and fresh" | `TestPasskeyDeleteOwnerScoped`, `TestPasskeyHTTPEndpoints` |
| "deleting a User removes credentials" | `TestUserDeletionRemovesPasskeys` |
| "passkey-only User can set initial password" | `TestPasskeyOnlyUserCanSetPassword` |
| "fresh passkey Session substitutes for current password" | `TestEmailChangeAcceptsFreshPasskeySession`, `TestEmailChangeRejectsStaleSession` |
| "go-webauthn verifier is used by default" | `TestPasskeyRealProtocolWiring` |
| "passkeys disabled by default" | `TestPasskeyDisabled` |
| "RP config validated at startup" | `TestPasskeysConfigValidation`, `TestPasskeyInvalidOriginRejectedAtStartup` |

## Security requirements → tests

| Requirement | Test |
| --- | --- |
| No new required Store method or schema migration | design: optional `PasskeyStore` and Token kinds only |
| Ceremony proof is single-use and expiring | `TestPasskeyRegistrationReplayRejected`, `TestPasskeySignInReplayRejected`, `TestPasskeyCeremonyExpiry` |
| Authenticator user verification required | design decision; verified by the pinned protocol library |
| Attestation not requested | design decision; verified by the pinned protocol library |
| Stale Session cannot enroll, list or delete | `TestPasskeyEnrollmentRequiresFreshSession`, `TestPasskeyDeleteOwnerScoped` |
| Unverified email cannot enroll | `TestPasskeyEnrollmentRequiresVerifiedEmail` |
| Cross-owner credential access denied | `TestPasskeyDeleteOwnerScoped` |
| Credential cleanup on User deletion | `TestUserDeletionRemovesPasskeys` |
| Denials and regressions are audited | `TestPasskeySignCountRegressionAudit` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Single-use ceremony token | second finish returns `ErrTokenInvalid` | `TestPasskeyRegistrationReplayRejected`, `TestPasskeySignInReplayRejected` |
| Ceremony expiry | expired proof rejected with injected Clock | `TestPasskeyCeremonyExpiry` |
| Freshness | stale session token denied | `TestPasskeyEnrollmentRequiresFreshSession`, `TestPasskeyDeleteOwnerScoped` |
| Session binding | fresh session cannot enroll another User | `TestPasskeyRegistrationBindsSessionUser` |
| Ceremony revocation | kinds joined to `AllTokenKinds` so revoke-all invalidates them | design: kinds added to the canonical list |
| Verified email gate | unverified User denied enrollment | `TestPasskeyEnrollmentRequiresVerifiedEmail` |
| Owner scoping | other User cannot delete credential | `TestPasskeyDeleteOwnerScoped` |
| Child record deletion | store empty after User deletion | `TestUserDeletionRemovesPasskeys` |
| Sign count regression | audit event emitted; sign-in still succeeds | `TestPasskeySignCountRegressionAudit` |
| Disabled feature | `ErrForbidden` rather than panic | `TestPasskeyDisabled` |
| Config validation | `ErrInvalidPasskeysConfig` at `New` | `TestPasskeysConfigValidation` |
| HTTP surface | all six endpoints work through `Handler()` | `TestPasskeyHTTPEndpoints` |

## Cross-cutting sweep

- [x] every rate-limited endpoint has a 429 test (no new rate-limited endpoint)
- [x] every exported sentinel has an errors.Is test (`ErrInvalidPasskeysConfig`)
- [x] every expiry branch is tested with the injected Clock
- [x] no token, password, link or verifier appears in logs
- [x] config defaults hold for a hand-built Config, not only DefaultConfig()
- [x] typed TypeScript client wrappers compile against the generated schema
- [x] backend code appears only in backend guides; frontend code only in the frontend guide
- [x] no internal ADR references on public docs pages
