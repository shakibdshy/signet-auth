package signet

import (
	"context"
	"net/http"
)

// RequireAuth is standard middleware that resolves the Session cookie,
// enforces its deadlines and attaches the authenticated User to the request.
func (c *Client) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := c.authenticate(w, r, true)
		if !ok {
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuth attaches the authenticated User when a valid Session is
// present and passes the request through otherwise.
func (c *Client) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := c.authenticate(w, r, false)
		if ok {
			ctx := context.WithValue(r.Context(), userContextKey{}, user)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func (c *Client) currentSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(c.cookieName())
	if err != nil || cookie.Value == "" {
		return nil, ErrNotFound
	}
	return c.sessions.ByHash(r.Context(), digestSecret(cookie.Value))
}

func (c *Client) authenticate(w http.ResponseWriter, r *http.Request, required bool) (*User, bool) {
	if c.csrf.Guard(w, r) {
		return nil, false
	}
	deny := func() (*User, bool) {
		if required {
			writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		}
		return nil, false
	}
	cookie, err := r.Cookie(c.cookieName())
	if err != nil || cookie.Value == "" {
		return deny()
	}
	user, err := c.sessions.Resolve(r.Context(), cookie.Value)
	if err != nil {
		return deny()
	}
	return user, true
}
