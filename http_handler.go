package signet

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/httpapi"
)

// Handler returns a plain http.Handler serving Signet's authentication endpoints.
func (c *Client) Handler() http.Handler {
	return httpapi.New(httpAdapter{Client: c}, c.cfg.PathPrefix).Handler()
}

// httpAdapter exposes the internal helpers the HTTP module needs without
// changing the public Client interface.
type httpAdapter struct{ *Client }

func (a httpAdapter) CSRFGuard(w http.ResponseWriter, r *http.Request) bool {
	return a.csrf.Guard(w, r)
}
func (a httpAdapter) ServeCSRFToken(w http.ResponseWriter, r *http.Request) { a.csrf.ServeToken(w, r) }
func (a httpAdapter) SetSessionCookies(w http.ResponseWriter, token string) (string, error) {
	return a.cookies.SetSessionAndCSRF(w, token)
}
func (a httpAdapter) CookieName() string { return a.cookies.Name() }
func (a httpAdapter) NewSessionCookie(token string, expiring bool) *http.Cookie {
	return a.cookies.SessionCookie(token, expiring)
}
func (a httpAdapter) ClearSessionCookie(w http.ResponseWriter) { a.cookies.ClearSessionCookie(w) }
func (a httpAdapter) Authenticate(w http.ResponseWriter, r *http.Request, required bool) (*core.User, bool) {
	return a.authenticate(w, r, required)
}
func (a httpAdapter) CurrentSession(r *http.Request) (*core.Session, error) {
	return a.currentSession(r)
}

// UserFromContext returns the authenticated User carried by a request context.
func UserFromContext(ctx context.Context) (*User, bool) {
	user, ok := httpapi.UserFromContext(ctx)
	return user, ok
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}
