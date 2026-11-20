package signet

import (
	"context"
	"net/http"
	"strings"
)

var authEndpoints = []string{
	"signup",
	"signin",
	"signout",
	"verify-email",
	"reset-password",
}

type userContextKey struct{}

// Handler returns a plain http.Handler serving Signet's authentication
// endpoints under Config.PathPrefix. Every endpoint returns 501 in this phase;
// behaviour arrives in later phases.
func (c *Client) Handler() http.Handler {
	prefix := strings.TrimRight(c.cfg.PathPrefix, "/")
	routes := make(map[string]bool, len(authEndpoints))
	for _, endpoint := range authEndpoints {
		routes[prefix+"/"+endpoint] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !routes[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "signet: endpoint not implemented", http.StatusNotImplemented)
	})
}

// RequireAuth is standard middleware for handlers that need an authenticated
// User. It passes requests through until Session resolution lands in Phase 2;
// it must not be relied on to enforce authentication yet.
func (c *Client) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// OptionalAuth is standard middleware that attaches an authenticated User to
// the request context when one is present. It passes requests through until
// Session resolution lands in Phase 2.
func (c *Client) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// UserFromContext returns the authenticated User carried by a request context,
// and reports whether one was present.
func UserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(userContextKey{}).(*User)
	return user, ok
}
