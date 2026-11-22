# Requirements coverage — Session and token hardening

Source: issues #59–#64. Design: `docs/superpowers/specs/2026-11-22-session-and-token-hardening-design.md`. ADR-0008 records the cache-authority decision.

Tests live in `tests/session_cache_test.go`, `tests/key_rotation_test.go`, `tests/redirect_patterns_test.go`, `internal/core/redirect_test.go` and `internal/csrf/csrf_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "cache off by default; TTL zero disables" | `TestSessionCacheDisabledUsesStore` |
| "cache hit skips the Store" | `TestSessionCacheHitSkipsStore` |
| "cache errors warn and fall back to the Store" | `TestSessionCacheErrorFallsBackToStore` |
| "Store errors reject" | `TestSessionStoreErrorRejectsRequest` |
| "every revocation flushes the cache" | `TestSessionCacheFlushOnRevokeSession`, `TestSessionCacheFlushOnRevokeAll`, `TestSessionCacheFlushOnSignOut`, `TestSessionCacheFlushOnPasswordReset`, `TestSessionCacheFlushOnPasswordChange`, `TestSessionCacheFlushOnAccountDeletion`, `TestSessionCacheFlushOnRefreshReuse` |
| "expired Sessions are never served from cache" | `TestSessionCacheHitSkipsStore` (deadline check in the cached value) |
| "legacy single key keeps working" | `TestJWTLegacySingleKeyStillWorks`, `TestKeyRingSignsWithFirstAndVerifiesAll` |
| "first key signs, all verify" | `TestJWTRingSignsWithFirstAndVerifiesOlderKey`, `TestKeyRingSignsWithFirstAndVerifiesAll` |
| "ring validation rejects empty/mixed/duplicate" | `TestJWTRingRejectsInvalidConfiguration` |
| "JWKS is opt-in and asymmetric-only" | `TestJWKSHandlerPublishesAsymmetricKeysOnly`, `TestJWKSHandlerEmptyForSymmetricKeys`, `TestJWKSPathIsNotMountedImplicitly` |
| "exact matches win, patterns are opt-in" | `TestRedirectPermittedPatterns`, `TestRedirectPatternAllowsMagicLinkSubdomain`, `TestRedirectPatternAllowsOAuthSubdomain` |
| "invalid patterns are rejected" | `TestValidateRedirectPatterns`, `TestRedirectPatternInvalidConfigurationRejected` |
| "no CSRF/AppURL widening" | `TestRedirectPatternRejectsMagicLinkLookalike`, `TestRedirectPermittedPatterns` |

## Security requirements → tests

| Requirement | Test or explained limitation |
| --- | --- |
| The Store is authoritative; a cache never grants access the Store would deny | `TestSessionCacheErrorFallsBackToStore`, `TestSessionStoreErrorRejectsRequest` |
| Revocation is observable across every deletion path | seven `TestSessionCacheFlushOn*` effect tests |
| Revocation lag is bounded by the configured TTL | limitation: cross-process revocation may take up to `CacheTTL`; the value is capped by the idle timeout and documented in [Sessions](/docs/sessions) |
| Rotating a key never invalidates live tokens | `TestJWTRingSignsWithFirstAndVerifiesOlderKey` |
| No private key material leaves the process | `TestJWKSHandlerPublishesAsymmetricKeysOnly` |
| Redirect patterns cannot widen CSRF or match lookalike hosts | `TestRedirectPatternRejectsMagicLinkLookalike`, `TestRedirectPermittedPatterns` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Digest-keyed Session cache | second authenticated request performs no Store read | `TestSessionCacheHitSkipsStore` |
| Cache fallback | request succeeds when the cache errors | `TestSessionCacheErrorFallsBackToStore` |
| Fail-closed Store | request returns 401 when the Store fails | `TestSessionStoreErrorRejectsRequest` |
| Namespace flush | cached Session rejected after each revocation path | seven `TestSessionCacheFlushOn*` tests |
| Ordered key ring | old-signed token verifies under a new ring | `TestJWTRingSignsWithFirstAndVerifiesOlderKey` |
| Asymmetric-only JWKS | only public keys appear; symmetric-only config is empty | `TestJWKSHandlerPublishesAsymmetricKeysOnly`, `TestJWKSHandlerEmptyForSymmetricKeys` |
| Pattern validation | invalid host/scheme patterns rejected at construction | `TestValidateRedirectPatterns`, `TestRedirectPatternInvalidConfigurationRejected` |

## Cross-cutting sweep

- [x] every opt-in surface has a disabled-by-default test
- [x] every exported sentinel has an errors.Is test (`TestJWTRingRejectsInvalidConfiguration`, `TestRedirectPatternInvalidConfigurationRejected`)
- [x] no secret, private key or token appears in JWKS or logs
- [x] Revocation lag and the Store-failure policy are documented
- [x] config defaults hold for a hand-built Config (`TestJWTLegacySingleKeyStillWorks` uses the helper Config)
