// Package store defines the persistence interfaces Signet uses to store users,
// sessions, and authentication tokens.
//
// Signet does not own your database schema: applications create and migrate their
// own tables, and adapters implement these interfaces against them. Consumers
// may also supply their own implementations, keeping the core library free of
// any database driver or ORM dependency.
package store
