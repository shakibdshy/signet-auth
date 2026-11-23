# Requirements coverage — Phase 8b Authorization server

Source: issue #102; tickets #103–#107. Tests live in `tests/oauth_server_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "Authorization server disabled by default" | `TestOAuthServerDisabled` |
| "client registry static or store" | `TestOAuthServerCodeExchange`, `TestOAuthServerHTTPEndpoints` |
| "PKCE S256 and allowlisted redirect" | `TestOAuthServerPKCEAndBinding` |
| "replayed code rejected" | `TestOAuthServerCodeExchange` |
| "refresh rotation and reuse containment" | `TestOAuthServerRefreshRotation` |
| "exact-string Scopes and audience allowlist" | `TestOAuthServerConsentAndScopes` |
| "trusted skip / untrusted consent + denial audit" | `TestOAuthServerConsentAndScopes` |
| "device lifecycle and approval" | `TestOAuthServerDeviceFlow` |
| "form and JSON wire formats" | `TestOAuthServerHTTPEndpoints` |

## Security requirements → tests

| Requirement | Test |
| --- | --- |
| Code bound to client, redirect, challenge, Scope and User | `TestOAuthServerPKCEAndBinding` |
| Single-use code | `TestOAuthServerCodeExchange` |
| Refresh reuse revokes family | `TestOAuthServerRefreshRotation` |
| Scope and audience rejection | `TestOAuthServerConsentAndScopes` |
| Consent denial audited | `TestOAuthServerConsentAndScopes` |
| Device code expiry and approval binding | `TestOAuthServerDeviceFlow` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| PKCE | wrong verifier rejected | `TestOAuthServerPKCEAndBinding` |
| Redirect allowlist | non-allowlisted URI denied | `TestOAuthServerPKCEAndBinding` |
| Single-use code | replay rejected | `TestOAuthServerCodeExchange` |
| Refresh rotation | reuse returns `ErrRefreshReuse` | `TestOAuthServerRefreshRotation` |
| Exact Scopes | unknown Scope and audience denied | `TestOAuthServerConsentAndScopes` |
| Consent | denial audited, approval required | `TestOAuthServerConsentAndScopes` |
| Device authorization | pending denied until approval | `TestOAuthServerDeviceFlow` |

## Cross-cutting sweep

- [x] generated artifacts and TS client rebuilt
- [x] backend code only in backend guides; frontend code only in frontend guide
- [x] no internal ADR references on public docs pages
