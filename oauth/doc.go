// Package oauth will hold Signet's OAuth provider implementations. Provider
// contracts, if any are exported, will live in the root signet package.
//
// Initial providers are planned for Google and GitHub. The interface will remain
// small and framework-agnostic so new providers can be added without changing
// Signet's core.
package oauth
