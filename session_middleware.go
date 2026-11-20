package signet

import (
	"context"
	"net/http"
)

// RequireAuth is standard middleware that resolves the Session cookie,
// enforces its idle and absolute deadlines, and attaches the authenticated
// User to the request context. Unauthenticated requests receive a generic 401.
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

// OptionalAuth is standard middleware that attaches the authenticated User
// when a valid Session cookie is present and passes the request through
// otherwise, including when no cookie is present.
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
	return c.cfg.Store.SessionByHash(r.Context(), digestSecret(cookie.Value))
}

func (c *Client) authenticate(w http.ResponseWriter, r *http.Request, required bool) (*User, bool) {
	if c.csrfRejected(w, r) {
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
	session, err := c.cfg.Store.SessionByHash(r.Context(), digestSecret(cookie.Value))
	if err != nil || session.RevokedAt != nil {
		return deny()
	}
	now := c.cfg.Clock.Now()
	if !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
		// Security: an expired Session is useless, so revoke it best-effort.
		_ = c.cfg.Store.DeleteSession(r.Context(), session.ID)
		return deny()
	}
	user, err := c.cfg.Store.UserByID(r.Context(), session.UserID)
	if err != nil || user.Disabled {
		return deny()
	}
	// Idle timeouts extend on activity; the absolute deadline is never touched.
	_ = c.cfg.Store.TouchSession(r.Context(), session.ID, now.Add(c.cfg.Session.IdleTimeout))
	return user, true
}
