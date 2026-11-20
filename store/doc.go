// Package store will hold Signet's persistence adapters. The persistence
// interfaces themselves are exported from the root signet package.
//
// Signet does not own your database schema: applications create and migrate their
// own tables, and adapters implement the root package's contracts against them.
// Consumers may also supply their own implementations, keeping the core library
// free of any database driver or ORM dependency.
package store
