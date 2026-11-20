# Public API lives in the root package

Every core public type, interface and function is exported from the root `signet` package; the `internal`, `store`, `mailer` and `oauth` directories hold private helpers and future adapters. This gives consumers one import for the core and avoids import cycles between the core and its adapters. The alternative — defining the interfaces in each adapter directory — was rejected because it would force the root package to import adapters or duplicate its contracts.

Adapter packages may export their own adapter types that implement root interfaces, as `hash/bcrypt` does with its `Hasher`. Such packages are optional: applications that use only the defaults still import just the root package. Phase 1 added this explicit allowance after the bcrypt adapter was introduced, since the original wording did not distinguish core API from optional adapters.

Test tooling is a second exemption: `store/conformance` exports `Run` so any Store implementation can be validated. It is a test helper, not part of the runtime API. Phase 5 added this allowance when the shared conformance suite was introduced.

The root façade was formalized in the 2026-11-20 folder reorganization: exported root names are type aliases of the private types in `internal/core`, and root methods delegate to private modules under `internal/` (`auth`, `session`, `token`, `oauth`, `csrf`, `mail`, `secret`, `httpapi`). This keeps the public import path and every exported name stable while allowing implementation files to move into real folders. Production packages under `internal/` must not import the root package, since that would form an import cycle; the test-only `internal/testutil` is the sole exception.
