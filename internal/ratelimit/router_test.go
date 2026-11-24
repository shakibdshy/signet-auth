package ratelimit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/shakibdshy/signet-auth/internal/core"
	"github.com/shakibdshy/signet-auth/internal/ratelimit"
)

type recordingLimiter struct {
	allowed bool
	keys    []string
}

func (l *recordingLimiter) Allow(_ context.Context, key string) (bool, error) {
	l.keys = append(l.keys, key)
	return l.allowed, nil
}

var errDenied = errors.New("denied")

func TestRoutingLimiterSelectsRule(t *testing.T) {
	fallback := &recordingLimiter{allowed: true}
	special := &recordingLimiter{allowed: false}
	router := ratelimit.New(fallback, map[string]core.RateLimitRule{
		"signin": {Limiter: special, KeyPrefix: "login"},
	})
	ok, err := router.Allow(context.Background(), "signin|1.2.3.4")
	if ok || err != nil {
		t.Fatalf("signin = %v, %v; want false,nil", ok, err)
	}
	if len(special.keys) != 1 || special.keys[0] != "login|1.2.3.4" {
		t.Fatalf("special keys = %v", special.keys)
	}
	if len(fallback.keys) != 0 {
		t.Fatalf("fallback called: %v", fallback.keys)
	}
	if ok, _ := router.Allow(context.Background(), "signup|1.2.3.4"); !ok {
		t.Fatal("fallback rule should allow signup")
	}
	if len(fallback.keys) != 1 || fallback.keys[0] != "signup|1.2.3.4" {
		t.Fatalf("fallback keys = %v", fallback.keys)
	}
}
