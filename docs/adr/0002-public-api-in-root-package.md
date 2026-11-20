# Public API lives in the root package

Every public type, interface and function is exported from the root `signet` package; the `internal`, `store`, `mailer` and `oauth` directories hold private helpers and future adapters only. This gives consumers one import and avoids import cycles between the core and its adapters. The alternative — defining the interfaces in each adapter directory — was rejected because it would force the root package to import adapters or duplicate its contracts.
