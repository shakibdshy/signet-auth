package signet

import "context"

// RateLimiter decides whether an action identified by a key may proceed.
type RateLimiter interface {
	// Allow reports whether the action for a key is within its limit.
	Allow(context.Context, string) (bool, error)
}
