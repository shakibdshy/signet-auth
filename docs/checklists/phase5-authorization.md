# Requirements coverage — Phase 5 authorization and API keys (PR #87)

Source: issues #82–#83. Design: `docs/superpowers/specs/2026-11-23-authorization-and-management-design.md`. ADR-0013 records the application-managed model.

Tests live in `tests/authorization_test.go` and `tests/api_key_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "Authorizer grants and denies" | `TestAuthorizerGrantsAndDenies` |
| "RoleWriter writes roles" | `TestRoleWriterSetsRoles` |
| "published permission constants" | `TestPermissionConstants` |
| "denied checks emit an Audit event" | `TestDeniedGuardedActionEmitsAudit` |
| "API keys are digest-only" | `TestAPIKeyRawNotStored` |
| "atomic verify and remaining count" | `TestAPIKeyCreateVerifyRevoke` |
| "API key permission and owner scoping" | `TestAPIKeyRequiresPermission`, `TestAPIKeyOwnerScoping` |

## Security requirements → tests

| Requirement | Test or explained limitation |
| --- | --- |
| No required Store method or schema migration | limitation verified by design: state is behind optional interfaces |
| Permissions are exact strings | `TestPermissionConstants` |
| API key raw value never stored | `TestAPIKeyRawNotStored` |
| API key use is atomic | `TestAPIKeyCreateVerifyRevoke` |
| System keys use a sentinel owner | `TestAPIKeyCreateVerifyRevoke` exercises issuance; sentinel applied before authorization |
| Denials are visible | `TestDeniedGuardedActionEmitsAudit` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Authorizer | grant succeeds, ungranted denies | `TestAuthorizerGrantsAndDenies` |
| RoleWriter split | writes go through separate interface | `TestRoleWriterSetsRoles` |
| Digest storage | raw key never appears in store | `TestAPIKeyRawNotStored` |
| Atomic consume | exhausted key rejected | `TestAPIKeyCreateVerifyRevoke` |
| Owner scoping | other owner cannot revoke | `TestAPIKeyOwnerScoping` |

## Cross-cutting sweep

- [x] every new exported sentinel has an errors.Is test
- [x] every new Config field is optional and tested
- [x] no secret, verifier or token appears in audit events or logs
