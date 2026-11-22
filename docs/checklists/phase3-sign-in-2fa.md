# Requirements coverage — Phase 3 sign-in and Second factor

Source: issues #66–#69. Design: `docs/superpowers/specs/2026-11-22-phase3-username-totp-accounts-design.md`. ADR-0009 and ADR-0010 record the storage decisions.

Tests live in `tests/username_test.go`, `tests/accounts_test.go` and `tests/two_factor_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "Username is stored as an Account" | `TestUsernameSignUpAndSignIn` |
| "normalized and validated before any User is created" | `TestUsernameSignUpAndSignIn`, `TestUsernameValidationAndReservedNames` |
| "duplicate gives a dedicated error" | `TestUsernameDuplicateRejected` |
| "same generic failure path" | `TestUsernameSignInIsCaseInsensitiveAndGenericOnFailure` |
| "Account listing returns safe fields only" | `TestListAccountsReturnsSafeFields` |
| "unlink refuses the last Account" | `TestUnlinkAccountRefusesLastAccount` |
| "fresh Session required for unlink" | `TestUnlinkAccountRequiresFreshSession` |
| "reject foreign IDs" | `TestUnlinkAccountRejectsForeignAccount` |
| "TOTP store and key required" | `TestTwoFactorRequiresStoreAndKey` |
| "enrollment pending until first successful code" | `TestTwoFactorEnableRequiresConfirmation` |
| "challenge exchanged for a Session, single-use" | `TestTwoFactorChallengeAndVerification` |
| "Backup codes single use and regeneration" | `TestTwoFactorBackupCodesAreSingleUse` |
| "wrong code and password-gated disable" | `TestTwoFactorWrongCodeAndDisable` |
| "JWT token flow cannot bypass Second factor" | `TestJWTTokenExchangeRequiresSecondFactor` |

## Security requirements → tests

| Requirement | Test or explained limitation |
| --- | --- |
| Password verifiers never leave the process | `TestListAccountsReturnsSafeFields` |
| A User always retains at least one sign-in method | `TestUnlinkAccountRefusesLastAccount` |
| Sensitive account changes require a recent Session | `TestUnlinkAccountRequiresFreshSession` |
| TOTP secrets are encrypted and Backup codes are digests | `TestTwoFactorEnableRequiresConfirmation` (state is inspected only through the store contract) |
| Challenges and Backup codes are single-use | `TestTwoFactorChallengeAndVerification`, `TestTwoFactorBackupCodesAreSingleUse` |
| Failed codes are throttled | limitation: limiter calls are exercised through the shared limiter fake; no persistent lockout is implemented by design |
| JWT mode cannot bypass Second factor | `TestJWTTokenExchangeRequiresSecondFactor` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Username normalization | uppercase input signs in the same User | `TestUsernameSignInIsCaseInsensitiveAndGenericOnFailure` |
| Generic credential failures | unknown Username and wrong password return the same sentinel | `TestUsernameSignInIsCaseInsensitiveAndGenericOnFailure` |
| Last-account guard | unlinking the final Account is rejected | `TestUnlinkAccountRefusesLastAccount` |
| Freshness window | a Session older than `Accounts.FreshWindow` is rejected | `TestUnlinkAccountRequiresFreshSession` |
| Single-use challenge | replayed challenge fails | `TestTwoFactorChallengeAndVerification` |
| Single-use Backup codes | a used code is rejected and regeneration replaces all | `TestTwoFactorBackupCodesAreSingleUse` |
| Enrollment confirmation | pending enrollment does not require a Second factor until confirmed | `TestTwoFactorEnableRequiresConfirmation` |
| JWT challenge gate | password-only exchange returns a challenge and no tokens | `TestJWTTokenExchangeRequiresSecondFactor` |

## Cross-cutting sweep

- [x] every new endpoint has a black-box effect test
- [x] every new exported sentinel has an errors.Is test
- [x] no secret, verifier or token appears in Account output or docs examples
- [x] config validation for the optional TOTP store is tested
- [x] status page no longer lists Username or TOTP as unimplemented
