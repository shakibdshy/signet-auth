# Requirements coverage — Phase 11 account controls and operations

Source: issue #123. Tests live in `tests/account_controls_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "UpdateUser via public API" | `TestUpdateUser` |
| "fresh Session belonging to that User" | `TestUpdateUser` |
| "SetPassword only without credential Account" | `TestSetAndVerifyPassword`, `TestSetPasswordForPasswordlessUser` |
| "VerifyPassword no Session" | `TestSetAndVerifyPassword` |
| "WindowLimiter backend selected" | `TestWindowLimiterUsed`, `TestWindowLimiterBlocks` |
| "QueryAudit bounded and fresh" | `TestQueryAudit` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Ownership | cross-user update denied | `TestUpdateUser` |
| Freshness | stale session denied | `TestUpdateUser`, `TestQueryAudit` |
| Credential gate | existing password denied | `TestSetAndVerifyPassword` |
| Anti-enumeration | unknown User verify returns false | `TestSetAndVerifyPassword` |
| Rate limiting | window limiter blocks sign-up | `TestWindowLimiterBlocks` |
| Audit query | filtered event returned | `TestQueryAudit` |
