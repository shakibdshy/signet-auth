package httpapi

import (
	"context"

	"github.com/shakibdshy/signet/internal/core"
)

type userContextKey struct{}
type principalContextKey struct{}

// WithUser attaches an authenticated User to a request context.
func WithUser(ctx context.Context, user *core.User) context.Context {
	return context.WithValue(ctx, userContextKey{}, user)
}

// UserFromContext returns the authenticated User carried by a request context.
func UserFromContext(ctx context.Context) (*core.User, bool) {
	user, ok := ctx.Value(userContextKey{}).(*core.User)
	return user, ok
}

// WithPrincipal attaches an API-key Principal to a request context.
func WithPrincipal(ctx context.Context, principal *core.Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

// PrincipalFromContext returns the API-key Principal carried by a request.
func PrincipalFromContext(ctx context.Context) (*core.Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(*core.Principal)
	return principal, ok
}
