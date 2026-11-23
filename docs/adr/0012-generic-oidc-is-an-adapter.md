# Generic OIDC is an adapter with fail-fast discovery and verified ID tokens

A generic Provider is an `oauth/oidc` adapter implementing the existing `OAuthProvider` interface. Discovery runs once in `oidc.NewProvider` and fails construction on error; an ID token is accepted only when it verifies against the discovered JWKS, issuer and client ID. If discovery provides no JWKS, the ID token is ignored and the identity comes from UserInfo.

We considered adding a generic provider block to core config and using a discovery library with per-request lazy fetching. Both would put network I/O and provider-specific policy into the core, add a dependency, and hide failures until a User tries to sign in. The adapter keeps Signet's seam unchanged and makes misconfiguration a startup error. The cost is that applications must construct the adapter explicitly and rebuild it if provider metadata changes, which is acceptable because OIDC metadata is stable in practice.
