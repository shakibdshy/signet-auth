// Package oauth defines the provider interface used for OAuth sign-in and hosts
// the built-in provider implementations.
//
// Initial providers are planned for Google and GitHub. The interface will remain
// small and framework-agnostic so new providers can be added without changing
// Signet's core.
package oauth
