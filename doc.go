// Package signet is the public entry point for github.com/shakibdshy/signet-auth,
// an embeddable authentication library for Go. It is not the Signet OAuth server
// or the cryptographic signing tools that also use the name "Signet".
//
// Signet is built on net/http primitives so it works with the standard library
// or any router. Applications create a Client once, supply a Store, Mailer and
// RateLimiter, and use the programmatic methods or mount the HTTP handler.
// Storage, mail delivery, password hashing and OAuth providers are pluggable.
package signet
