# Requirements coverage — foundation (#44)

Source: GitHub issue #44 and children #46–#51. Every row names an existing test or an accepted limitation.

| Requirement | Test / limitation |
| --- | --- |
| Email change request validates current password, email format and uniqueness | tests/email_change_test.go: TestEmailChangeRequestRejectsInvalidInputs, TestEmailChangeTakenAddressUsesGenericError |
| Email change keeps old email active until verification | tests/email_change_test.go: TestEmailChangeRequestAndVerify |
| Email change Token single-use and replay rejected | tests/email_change_test.go: TestEmailChangeVerifySingleUseAndUniqueness |
| Uniqueness re-checked at consume time | tests/email_change_test.go: TestEmailChangeUniquenessRaceAtConsume |
| Email change HTTP auth and CSRF | tests/email_change_test.go: TestEmailChangeHTTPEndpoints, TestEmailChangeHTTPRequiresAuthAndCSRF |
| Opaque Token data round-trip and tamper detection | internal/token/data_test.go: TestIssueWithDataRoundTrip |
| Email normalization | internal/auth/email_change_test.go: TestNormalizeEmailForChange |
| Account deletion removes children in ADR 0006 order | tests/account_deletion_test.go: TestDeleteUserRemovesChildrenExplicitly |
| Invalid deletion Token has no side effects | tests/account_deletion_test.go: TestDeleteUserRejectsBadTokensWithoutMutation |
| Failed child deletion fails loud and leaves no Session | tests/account_deletion_test.go: TestDeleteUserFailureLeavesNoLiveSession |
| Account deletion HTTP auth and CSRF | tests/account_deletion_test.go: TestDeleteUserHTTPEndpoints |
| Freshness disabled by default | tests/fresh_session_test.go: TestFreshSessionWindowDisabledByDefault |
| Freshness uses CreatedAt not LastSeenAt | tests/fresh_session_test.go: TestFreshSessionUsesCreatedAt; internal/session/fresh_test.go: TestIsFreshUsesCreatedAtNotLastSeen |
| Freshness middleware protects routes and rejects forged cookies | tests/fresh_session_test.go: TestFreshSessionMiddleware, TestFreshSessionMiddlewareRejectsForgedCookieWithDefaultConfig |
| Rate-limit rule selection and default fallback | internal/ratelimit/router_test.go: TestRoutingLimiterSelectsRule |
| Per-endpoint rule applies using published names | tests/rate_limit_rules_test.go: TestPerEndpointRateLimit, TestPublishedEndpointNameRuleApplies |
| Unknown rule key rejected | tests/rate_limit_rules_test.go: TestUnknownRateLimitRuleKeyRejected |
| XFF ignored without trusted proxies | internal/httpapi/clientip_test.go: TestResolveClientIP; tests/trusted_proxy_test.go: TestNoTrustedProxiesIgnoresXFF |
| Trusted proxy chain, spoofing and IPv6 normalization | internal/httpapi/clientip_test.go: TestResolveClientIP; tests/trusted_proxy_test.go: TestTrustedProxyUsesForwardedKey |
| Contract and generated artifacts current | make generate-check; docs-site/scripts/check-docs-coverage.mjs |

## Accepted limitations

- Deployed with `FreshAge == 0`, `VerifyFreshSession` validates the Session exists but skips the time comparison; applications wanting protection must set a window.
- Request-time email uniqueness returns generic `invalid_input`; the distinguishing `email_exists` is deferred to consume time where the Token proves address control.
- Rate-limit limiter keys now use published endpoint names; applications with custom limiter logic keyed on old internal names must update those keys.
