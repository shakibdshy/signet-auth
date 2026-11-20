// Package internal holds private implementation helpers shared across Signet.
//
// Its contents are intentionally hidden from library consumers by Go's internal
// package rules. Cryptographic helpers, token encoding, and other low-level
// building blocks will live here; the supported API is the module root.
package internal
