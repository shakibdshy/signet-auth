# Requirements coverage — Phase 9 SAML Web SSO

Source: issue #115; tickets #116–#119. Tests live in `tests/saml_test.go`.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| "SAML disabled by default" | `TestSAMLDisabled` |
| "connection protocol discriminator" | `TestSAMLEnabledAndConnectionRequiresMetadata` |
| "OIDC connection cannot start SAML" | `TestSAMLOIDCConnectionCannotStartSAML` |
| "pinned metadata required" | `TestSAMLEnabledAndConnectionRequiresMetadata` |
| "signed assertion accepted" | `TestSAMLSignedAssertionEffect` |
| "unsigned assertion rejected" | `TestSAMLRejectsUnsignedAssertion` |
| "unverified email rejected" | `TestSAMLRejectsUnverifiedEmail` |
| "InResponseTo bound" | `TestSAMLRejectsWrongInResponseTo` |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| Opt-in | disabled denies sign-in | `TestSAMLDisabled` |
| Protocol binding | OIDC connection cannot start SAML flow | `TestSAMLOIDCConnectionCannotStartSAML` |
| Metadata pinning | start without metadata denied | `TestSAMLEnabledAndConnectionRequiresMetadata` |
| Assertion signature | unsigned assertion rejected | `TestSAMLRejectsUnsignedAssertion` |
| Verified email | unverified attribute rejected | `TestSAMLRejectsUnverifiedEmail` |
| InResponseTo binding | wrong request ID rejected | `TestSAMLRejectsWrongInResponseTo` |
| JIT provisioning | signed assertion creates Session and active org | `TestSAMLSignedAssertionEffect` |

