package httpapi

import (
	"net/http"
	"time"

	"github.com/shakibdshy/signet/internal/csrf"
)

// Cookies builds and clears Signet's session cookie and issues the CSRF
// cookie alongside it. The session name is resolved once by New.
type Cookies struct {
	guard       *csrf.Guard
	sessionName string
	path        string
	domain      string
	secure      bool
	httpOnly    bool
	sameSite    http.SameSite
	jwtOnly     bool
}

// NewCookies returns a Cookies helper. sessionName is the already-resolved
// cookie name, including any __Host- prefix.
func NewCookies(guard *csrf.Guard, sessionName, path, domain string, secure, httpOnly bool, sameSite http.SameSite, jwtOnly bool) *Cookies {
	return &Cookies{
		guard: guard, sessionName: sessionName, path: path, domain: domain,
		secure: secure, httpOnly: httpOnly, sameSite: sameSite, jwtOnly: jwtOnly,
	}
}

// Name returns the resolved session cookie name.
func (c *Cookies) Name() string { return c.sessionName }

// SessionCookie builds the session cookie with the shared policy. All
// attributes come from validated Config; clearing also sets MaxAge and Expires.
//
//nolint:gosec // G124: validated config drives every attribute.
func (c *Cookies) SessionCookie(value string, expiring bool) *http.Cookie {
	cookie := &http.Cookie{
		Name:     c.sessionName,
		Value:    value,
		Path:     c.path,
		Domain:   c.domain,
		Secure:   c.secure,
		HttpOnly: c.httpOnly,
		SameSite: c.sameSite,
	}
	if expiring {
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(1, 0)
	}
	return cookie
}

// SetSessionAndCSRF writes the CSRF cookie and the session cookie together.
func (c *Cookies) SetSessionAndCSRF(w http.ResponseWriter, sessionToken string) (string, error) {
	if c.jwtOnly {
		return "", nil
	}
	csrfToken, err := c.guard.IssueAndSetCookie(w)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, c.SessionCookie(sessionToken, false))
	return csrfToken, nil
}

// ClearSessionCookie expires the session cookie. JWT-only mode issues none.
func (c *Cookies) ClearSessionCookie(w http.ResponseWriter) {
	if c.jwtOnly {
		return
	}
	http.SetCookie(w, c.SessionCookie("", true))
}
