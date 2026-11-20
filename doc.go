// Package signet is the public entry point for an embeddable authentication
// library for Go.
//
// Signet is built on net/http primitives so it can be used with the standard
// library or any router. The API is intentionally small: lower-level building
// blocks live in the internal tree, while storage, mail delivery, and OAuth
// providers are exposed as pluggable packages.
//
// This repository currently contains the project foundation only. No
// authentication functionality is available yet.
package signet
