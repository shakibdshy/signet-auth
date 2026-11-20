// Package postgres will provide a PostgreSQL-backed implementation of Signet's
// store interfaces.
//
// Following Signet's "bring your own schema" principle, the adapter will operate
// against tables owned and migrated by the application rather than imposing its
// own migration system.
package postgres
