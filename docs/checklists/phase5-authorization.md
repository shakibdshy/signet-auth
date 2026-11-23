# Requirements coverage — Phase 5 authorization and API keys (PR #87)

Source: issues #82–#83. Design: `docs/superpowers/specs/2026-11-23-authorization-and-management-design.md`. ADR-0013 records the application-managed model.

Tests live in `tests/authorization_test.go` and `tests/api_key_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "Authorizer grants and denies" | `TestAuthorizerGrantsAndDenies` |
| "RoleWriter writes roles" | `TestRoleWriterSetsRoles` |
| "published permission constants" | `TestPermissionConstants` |
| "denied checks emit an Audit event with outcome denied" | `TestAuthorizeDenialEmitsAudit`, `TestDeniedGuardedActionEmitsAudit` |
| "default in-memory authorizer from statements + callback" | `TestMemoryAuthorizerFromStatements` |
| "AuthorizeIn extension without changing Authorizer" | `TestAuthorizeInWiring` |
| "API keys are digest-only" | `TestAPIKeyRawNotStored` |
| "one atomic ConsumeAPIKey(ctx, digest) call" | `TestAPIKeyCreateVerifyRevoke`, `TestAPIKeyExpiredAndMissing` |
| "API key permission and owner scoping" | `TestAPIKeyRequiresPermission`, `TestAPIKeyOwnerScoping` |
| "HTTP endpoints for create, list, revoke and verification" | `TestAPIKeyHTTPEndpoints`, `TestAPIKeyRevokeHTTPEndpoint` |
| "opt-in per-route middleware; session cookie ignored" | `TestAPIKeyMiddleware`, `TestAPIKeyProtectedRouteIgnoresSession` |
| "state-changing operations need a fresh Session and emit audits" | `TestAPIKeyRequiresFreshSession`, `TestAPIKeySuccessAudit` |
| "system key with no owner uses a published sentinel ID" | `TestSystemAPIKeyUsesSentinelOwner` |

## Security requirements → tests

| Requirement | Test |
| --- | --- |
| No required Store method or schema migration | limitation verified by design: state is behind optional interfaces |
| Permissions are exact strings | `TestPermissionConstants` |
| API key raw value never stored (including prefix) | `TestAPIKeyRawNotStored` |
| API key use is atomic and rejects expired/missing keys | `TestAPIKeyCreateVerifyRevoke`, `TestAPIKeyExpiredAndMissing` |
| System keys use a sentinel owner before authorization | `TestSystemAPIKeyUsesSentinelOwner` |
| Denials are visible | `TestAuthorizeDenialEmitsAudit`, `TestDeniedGuardedActionEmitsAudit` |
| Successful state changes are audited | `TestAPIKeySuccessAudit` |
| Protected routes ignore session cookies | `TestAPIKeyProtectedRouteIgnoresSession` |
| Stale sessions cannot issue keys | `TestAPIKeyRequiresFreshSession` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Authorizer | grant succeeds, ungranted denies | `TestAuthorizerGrantsAndDenies` |
| RoleWriter split | writes go through separate interface | `TestRoleWriterSetsRoles` |
| Memory authorizer | exact statement grants only | `TestMemoryAuthorizerFromStatements` |
| AuthorizeIn | optional extension is wired and callable | `TestAuthorizeInWiring` |
| Digest storage | raw key never appears in store | `TestAPIKeyRawNotStored` |
| Atomic consume | exhausted, expired and missing keys rejected | `TestAPIKeyCreateVerifyRevoke`, `TestAPIKeyExpiredAndMissing` |
| Owner scoping | other owner cannot revoke | `TestAPIKeyOwnerScoping` |
| Denied audit | guarded denial emits `outcome: denied` with permission metadata | `TestDeniedGuardedActionEmitsAudit` |
| Success audit | create and revoke emit `outcome: success` events | `TestAPIKeySuccessAudit` |
| Key middleware | missing key rejected, valid key accepted, session ignored | `TestAPIKeyMiddleware`, `TestAPIKeyProtectedRouteIgnoresSession` |
| Freshness | stale session token rejected | `TestAPIKeyRequiresFreshSession` |
| Sentinel | empty owner authorized under `SystemOwnerID` | `TestSystemAPIKeyUsesSentinelOwner` |
| ErrForbidden | distinct sentinel with `signet: forbidden` text | `TestForbiddenSentinelIsDistinct` |

## Cross-cutting sweep

- [x] every new exported sentinel has an errors.Is test
- [x] every new Config field is optional and tested
- [x] no secret, verifier or raw key appears in audit events or logs
- [x] new behaviour lives in `internal/authorization`, façade delegates only
- [x] generated OpenAPI describes statuses generically, not one arbitrary error code
