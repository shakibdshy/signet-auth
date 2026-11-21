// Package ratelimit routes rate-limit decisions to per-endpoint limiters.
package ratelimit

import (
	"context"
	"strings"

	"github.com/shakibdshy/signet/internal/core"
)

type router struct {
	fallback core.RateLimiter
	rules    map[string]core.RateLimitRule
}

// New returns a RateLimiter that selects a rule by the endpoint prefix of
// keys shaped "endpoint|client". Unknown endpoints use the fallback limiter.
func New(fallback core.RateLimiter, rules map[string]core.RateLimitRule) core.RateLimiter {
	return &router{fallback: fallback, rules: rules}
}

func (r *router) Allow(ctx context.Context, key string) (bool, error) {
	endpoint, rest, found := strings.Cut(key, "|")
	if !found {
		return r.fallback.Allow(ctx, key)
	}
	rule, ok := r.rules[endpoint]
	if !ok {
		return r.fallback.Allow(ctx, key)
	}
	limiter := rule.Limiter
	if limiter == nil {
		limiter = r.fallback
	}
	prefix := endpoint
	if rule.KeyPrefix != "" {
		prefix = rule.KeyPrefix
	}
	return limiter.Allow(ctx, prefix+"|"+rest)
}
