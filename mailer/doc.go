// Package mailer defines the interface Signet will use to deliver transactional
// email, such as verification links and password-reset messages.
//
// Applications can plug in any delivery mechanism by implementing that
// interface: SMTP, a third-party email API, or a no-op implementation for tests.
package mailer
