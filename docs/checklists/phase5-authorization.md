# Requirements coverage — Phase 5 authorization and management

Source: issues #82–#86. Design: `docs/superpowers/specs/2026-11-23-authorization-and-management-design.md`. ADR-0013 records the application-managed model.

Tests live in `tests/authorization_test.go`, `tests/api_key_test.go`, `tests/organization_test.go` and `tests/admin_test.go`.

## Testing Decisions → tests

### Authorization core and API keys (#82, #83)

| Spec line (short quote) | Test |
| --- | --- |
| "Authorizer grants and denies" | `TestAuthorizerGrantsAndDenies` |
| "RoleWriter writes roles" | `TestRoleWriterSetsRoles` |
| "published permission constants" | `TestPermissionConstants` |
| "denied checks emit an Audit event with outcome denied" | `TestAuthorizeDenialEmitsAudit`, `TestDeniedGuardedActionEmitsAudit` |
| "default in-memory authorizer from statements + callback" | `TestMemoryAuthorizerFromStatements` |
| "AuthorizeIn extension without changing Authorizer" | `TestAuthorizeInWiring` |
| "API keys are digest-only" | `TestAPIKeyRawNotStored`, `TestAPIKeyPrefixIsNotRaw` |
| "one atomic ConsumeAPIKey(ctx, digest) call" | `TestAPIKeyVerifyUsesSingleAtomicStoreCall`, `TestAPIKeyExpiredAndMissing` |
| "API key permission and owner scoping" | `TestAPIKeyRequiresPermission`, `TestAPIKeyOwnerScoping` |
| "HTTP endpoints for create, list, revoke and verification" | `TestAPIKeyHTTPEndpoints`, `TestAPIKeyListAndVerifyHTTPEndpoints`, `TestAPIKeyRevokeHTTPEndpoint` |
| "opt-in per-route middleware; session cookie ignored" | `TestAPIKeyMiddleware`, `TestAPIKeyProtectedRouteIgnoresSession` |

### Organizations (#84)

| Spec line (short quote) | Test |
| --- | --- |
| "optional organization store; nil disables" | `TestOrganizationCreateMemberAndActive`, `TestOrganizationTamperedCookieIgnored` |
| "SetActiveOrganization verifies membership before cookie" | `TestOrganizationSetActiveRejectsNonMember`, `TestOrganizationCreateMemberAndActive` |
| "every org-scoped check re-reads membership" | `TestOrganizationUsesAuthorizeIn`, `TestOrganizationSetActiveRejectsNonMember` |
| "organization-aware authorization extension" | `TestOrganizationUsesAuthorizeIn` |
| "HTTP endpoints for create/list/member/role/active clear" | `TestOrganizationHTTPEndpoints` |
| "tampered or stale cookies treated as absent" | `TestOrganizationTamperedCookieIgnored` |
| "fresh Session for org mutations" | `TestOrganizationMutationsRequireFreshSession` |
| "success and denial audit events" | `TestOrganizationAuditSuccessAndDenial` |

### Admin management (#85)

| Spec line (short quote) | Test |
| --- | --- |
| "Go methods and HTTP endpoints for all admin actions" | `TestAdminHTTPEndpoints`, `TestAdminBanUnbanAndSelfBlock`, `TestAdminListRevokeSessions` |
| "grant, fresh Session and Audit on state changes" | `TestAdminDeniedAudit`, `TestAdminStaleSessionBlocked`, `TestAdminBanUnbanAndSelfBlock` |
| "self-ban and self-delete blocked" | `TestAdminBanUnbanAndSelfBlock`, `TestSelfDeleteBlockedWhileImpersonating` |
| "impersonation creates Store-backed Session + signed cookie" | `TestImpersonationUsesStoreSessionAndSignedCookie` |
| "stop revokes temp Session and restores original" | `TestImpersonationUsesStoreSessionAndSignedCookie` |
| "admin checks use admin ID from cookie" | `TestImpersonationUsesStoreSessionAndSignedCookie` |
| "self-impersonation blocked" | `TestSelfImpersonationBlocked` |
| "black-box effects for missing grants" | `TestAdminBanRequiresGrant`, `TestAdminSetRoleRequiresGrant`, `TestAdminDeniedAudit` |

## Security requirements → tests

| Requirement | Test |
| --- | --- |
| No required Store method or schema migration | design: all new state behind optional interfaces |
| Permissions are exact strings | `TestPermissionConstants` |
| API key raw value never stored (including prefix) | `TestAPIKeyRawNotStored`, `TestAPIKeyPrefixIsNotRaw` |
| API key use atomic; expired/missing keys rejected | `TestAPIKeyVerifyUsesSingleAtomicStoreCall`, `TestAPIKeyExpiredAndMissing` |
| System keys use sentinel owner | `TestSystemAPIKeyUsesSentinelOwner` |
| Denials visible | `TestAuthorizeDenialEmitsAudit`, `TestDeniedGuardedActionEmitsAudit`, `TestAdminDeniedAudit` |
| Successful state changes audited | `TestAPIKeySuccessAudit`, `TestOrganizationAuditSuccessAndDenial`, `TestAdminBanUnbanAndSelfBlock` |
| Protected routes ignore session cookies | `TestAPIKeyProtectedRouteIgnoresSession` |
| Stale sessions cannot issue keys or mutate orgs/users | `TestAPIKeyRequiresFreshSession`, `TestOrganizationMutationsRequireFreshSession`, `TestAdminStaleSessionBlocked` |
| Membership verified before org writes | `TestOrganizationSetActiveRejectsNonMember`, `TestOrganizationUsesAuthorizeIn` |
| Impersonation cookie is signed and tamper-evident | `TestImpersonationUsesStoreSessionAndSignedCookie` |
| Self-service deletion disabled while impersonating | `TestSelfDeleteBlockedWhileImpersonating` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Authorizer | grant succeeds, ungranted denies | `TestAuthorizerGrantsAndDenies` |
| RoleWriter split | writes go through separate interface | `TestRoleWriterSetsRoles` |
| Memory authorizer | exact statement grants only | `TestMemoryAuthorizerFromStatements` |
| AuthorizeIn | extension called for org-scoped check | `TestOrganizationUsesAuthorizeIn` |
| Digest storage | raw key never appears in hash or prefix | `TestAPIKeyRawNotStored`, `TestAPIKeyPrefixIsNotRaw` |
| Atomic consume | exactly one store call; exhausted/expired/missing rejected | `TestAPIKeyVerifyUsesSingleAtomicStoreCall`, `TestAPIKeyExpiredAndMissing` |
| Owner scoping | other owner cannot revoke | `TestAPIKeyOwnerScoping` |
| Denied audit | guarded denial emits `outcome: denied` with permission metadata | `TestDeniedGuardedActionEmitsAudit`, `TestAdminDeniedAudit` |
| Success audit | create/revoke/org/admin emit `outcome: success` | `TestAPIKeySuccessAudit`, `TestOrganizationAuditSuccessAndDenial` |
| Key middleware | missing key rejected, valid key accepted, session ignored | `TestAPIKeyMiddleware`, `TestAPIKeyProtectedRouteIgnoresSession` |
| Freshness | stale token rejected for writes and listing | `TestAPIKeyRequiresFreshSession`, `TestOrganizationMutationsRequireFreshSession`, `TestAdminStaleSessionBlocked` |
| Membership verification | non-member cannot select active org | `TestOrganizationSetActiveRejectsNonMember` |
| Signed active-org cookie | tampered cookie treated as absent | `TestOrganizationTamperedCookieIgnored` |
| Signed impersonation cookie | admin ID + original token round-trip; tampering ignored | `TestImpersonationUsesStoreSessionAndSignedCookie` |
| Impersonation lifecycle | temp Session created and revoked; original restored | `TestImpersonationUsesStoreSessionAndSignedCookie` |
| Self-action blocks | self-ban and self-impersonation denied | `TestAdminBanUnbanAndSelfBlock`, `TestSelfImpersonationBlocked` |

## Cross-cutting sweep

- [x] every new exported sentinel has an errors.Is test
- [x] every new Config field is optional and tested
- [x] no secret, verifier or raw key appears in audit events or logs
- [x] new behaviour lives in `internal/authorization` and `internal/orgadmin`; façade delegates only
- [x] generated OpenAPI describes statuses generically, not one arbitrary error code
- [x] all new endpoints have a black-box effect test
- [x] `docs-site/content/docs/status.mdx` and research wording show all phases shipped
