// Package mailer will hold Signet's email delivery implementations. The Mailer
// interface and Message type are exported from the root signet package.
//
// Applications can plug in any delivery mechanism by implementing that
// interface: SMTP, a third-party email API, or a no-op implementation for tests.
package mailer
