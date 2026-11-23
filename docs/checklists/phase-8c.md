# Requirements coverage — Phase 8c Organization SSO

Source: issue #109; tickets #110–#113. Tests live in `tests/sso_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "SSO disabled by default" | `TestSSODisabled` |
| "connection config in optional store" | `TestSSOConnectionAndSignIn` |
| "fail-closed domain verification" | `TestSSODomainNotVerified` |
| "start with email or Organization ID" | `TestSSOConnectionAndSignIn`, `TestSSOHTTPEndpoints` |
| "generic failure for unknown connections" | `TestSSOUnknownConnectionGeneric` |
| "single-use state token" | `TestSSOConnectionAndSignIn` |
| "verified email JIT provisioning" | `TestSSOConnectionAndSignIn` |
| "unverified email rejected" | `TestSSOUnverifiedEmailRejected` |
| "connections require fresh Session" | `TestSSOConnectionCRUDRequiresFreshSession` |
| "HTTP and typed client surface" | `TestSSOHTTPEndpoints` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Opt-in | disabled denies sign-in | `TestSSODisabled` |
| Domain verification | unverified domain denied | `TestSSODomainNotVerified` |
| Anti-enumeration | unknown domain denied generically | `TestSSOUnknownConnectionGeneric` |
| Single-use state | replayed callback rejected | `TestSSOConnectionAndSignIn` |
| Verified email | unverified assertion rejected | `TestSSOUnverifiedEmailRejected` |
| Freshness | stale session cannot manage connections | `TestSSOConnectionCRUDRequiresFreshSession` |

## Cross-cutting sweep

- [x] generated artifacts and TS client rebuilt
- [x] backend code only in backend guides; frontend code only in frontend guide
- [x] no internal ADR references on public docs pages
