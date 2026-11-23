# Requirements coverage — Phase 4 generic OIDC provider

Source: issues #77–#80. Design: `docs/superpowers/specs/2026-11-23-generic-oidc-provider-design.md`. ADR-0012 records the adapter decision.

Tests live in `tests/oidc_test.go` and `tests/oidc_identity_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "Provider discovery reads endpoints and issuer" | `TestOIDCDiscoverySuccess` |
| "discovery failure fails construction" | `TestOIDCDiscoveryFailureFailsConstruction` |
| "HTTPS required, redirects refused" | `TestOIDCDiscoveryRejectsHTTPAndRedirect` |
| "explicit overrides win" | `TestOIDCExplicitEndpointsOverrideDiscovery` |
| "issuer mismatch fails" | `TestOIDCIssuerMismatchRejected` |
| "algorithm allowlist, none and HS256 rejected" | `TestOIDCAlgorithmRejection` |
| "ProviderID unique and not reserved" | `TestOIDCProviderIDConflicts`, `TestOIDCReservedProviderNameRejected` |
| "nonce bound to sealed state" | `TestOAuthStartSendsNonce`, `TestOAuthCallbackPassesNonceToProvider` |
| "OpenID and PKCE in authorization URL" | `TestOIDCAuthorizationURLHasNonceAndOpenID` |
| "verified ID token supplies identity" | `TestOIDCIdentityVerifiedIDToken` |
| "bad token claims rejected" | `TestOIDCIdentityRejectsBadTokenClaims` |
| "UserInfo fallback" | `TestOIDCIdentityUserInfoFallback` |
| "JWKS failure is hard error" | `TestOIDCIdentityJWKSFailureIsHardError` |

## Security requirements → tests

| Requirement | Test or explained limitation |
| --- | --- |
| No new core config field or schema | verified by design; the adapter is registered through the existing `OAuthConfig.Providers` |
| Discovery cannot be downgraded to HTTP or redirected | `TestOIDCDiscoveryRejectsHTTPAndRedirect` |
| Issuer and algorithm conflicts fail at startup | `TestOIDCIssuerMismatchRejected`, `TestOIDCAlgorithmRejection` |
| PKCE and nonce are single-use and bound to state | `TestOAuthStartSendsNonce`, `TestOAuthCallbackPassesNonceToProvider`, existing OAuth state tests |
| ID-token verification is fail-closed | `TestOIDCIdentityRejectsBadTokenClaims`, `TestOIDCIdentityJWKSFailureIsHardError` |
| Provider IDs cannot shadow built-ins | `TestOIDCReservedProviderNameRejected`, `TestOIDCProviderIDConflicts` |
| Existing adapters are unchanged | full existing OAuth suite remains green |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Fail-fast discovery | construction error on unreachable or invalid metadata | `TestOIDCDiscoveryFailureFailsConstruction` |
| HTTPS/no-redirect policy | HTTP and redirecting metadata rejected | `TestOIDCDiscoveryRejectsHTTPAndRedirect` |
| Algorithm allowlist | `none`, HS256 and unsupported values rejected | `TestOIDCAlgorithmRejection` |
| Nonce binding | callback passes state nonce to the provider; mismatch fails | `TestOAuthCallbackPassesNonceToProvider`, `TestOIDCIdentityRejectsBadTokenClaims` |
| ID-token verification | wrong issuer, audience, expiry or subject fails | `TestOIDCIdentityRejectsBadTokenClaims` |
| Fail-closed JWKS | fetch failure rejects the request | `TestOIDCIdentityJWKSFailureIsHardError` |
| Provider uniqueness | duplicate or reserved IDs rejected by `New` | `TestOIDCProviderIDConflicts` |

## Cross-cutting sweep

- [x] every new endpoint behaviour has a black-box effect test
- [x] every new exported sentinel has an errors.Is test
- [x] no secret, token or code appears in audit events or logs
- [x] HTTPS policy applies to discovery, JWKS, UserInfo and overrides
- [x] status and research pages reflect shipped Phase 4 and remaining Phase 5
