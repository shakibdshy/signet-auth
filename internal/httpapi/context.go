package httpapi

import (
	"context"

	"github.com/shakibdshy/signet/internal/core"
)

type userContextKey struct{}

// WithUser attaches an authenticated User to a request context.
func WithUser(ctx context.Context, user *core.User) context.Context {
	return context.WithValue(ctx, userContextKey{}, user)
}

// UserFromContext returns the authenticated User carried by a request context.
func UserFromContext(ctx context.Context) (*core.User, bool) {
	user, ok := ctx.Value(userContextKey{}).(*core.User)
	return user, ok
}
