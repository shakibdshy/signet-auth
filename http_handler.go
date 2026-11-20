package signet

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/httpapi"
)

type userContextKey struct{}

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
	return a.setSessionAndCSRFCookies(w, token)
}
func (a httpAdapter) CookieName() string { return a.cookieName() }
func (a httpAdapter) NewSessionCookie(token string, expiring bool) *http.Cookie {
	return a.sessionCookie(token, expiring)
}
func (a httpAdapter) ClearSessionCookie(w http.ResponseWriter) { a.clearSessionCookie(w) }
func (a httpAdapter) Authenticate(w http.ResponseWriter, r *http.Request, required bool) (*core.User, bool) {
	return a.authenticate(w, r, required)
}
func (a httpAdapter) CurrentSession(r *http.Request) (*core.Session, error) {
	return a.currentSession(r)
}

func (c *Client) setSessionAndCSRFCookies(w http.ResponseWriter, sessionToken string) (string, error) {
	if c.cfg.JWTOnly {
		return "", nil
	}
	csrfToken, err := c.csrf.IssueAndSetCookie(w)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, c.sessionCookie(sessionToken, false))
	return csrfToken, nil
}

func (c *Client) useHostPrefix() bool {
	return c.cfg.Cookie.Secure && c.cfg.Cookie.Path == "/" && c.cfg.Cookie.Domain == ""
}

func (c *Client) cookieName() string {
	if c.useHostPrefix() {
		return "__Host-" + c.cfg.Cookie.Name
	}
	return c.cfg.Cookie.Name
}

//nolint:gosec // G124: all attributes come from validated Config; clearing also sets MaxAge and Expires.
func (c *Client) sessionCookie(value string, expiring bool) *http.Cookie {
	cookie := &http.Cookie{
		Name:     c.cookieName(),
		Value:    value,
		Path:     c.cfg.Cookie.Path,
		Domain:   c.cfg.Cookie.Domain,
		Secure:   c.cfg.Cookie.Secure,
		HttpOnly: c.cfg.Cookie.HttpOnly,
		SameSite: c.cfg.Cookie.SameSite,
	}
	if expiring {
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(1, 0)
	}
	return cookie
}

func (c *Client) clearSessionCookie(w http.ResponseWriter) {
	if c.cfg.JWTOnly {
		return
	}
	http.SetCookie(w, c.sessionCookie("", true))
}

// UserFromContext returns the authenticated User carried by a request context.
func UserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(userContextKey{}).(*User)
	return user, ok
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}
