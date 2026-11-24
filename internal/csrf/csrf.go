// Package csrf implements Signet's signed double-submit CSRF guard.
package csrf

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/shakibdshy/signet-auth/internal/core"
)

const ttl = 12 * time.Hour

// ValidateKeys checks that a CSRF key ring is non-empty, 32-byte and unique.
func ValidateKeys(keys [][]byte) error {
	if len(keys) == 0 {
		return core.ErrInvalidCSRFConfig
	}
	for i, key := range keys {
		if len(key) != 32 {
			return core.ErrInvalidCSRFConfig
		}
		for _, earlier := range keys[:i] {
			if bytes.Equal(earlier, key) {
				return core.ErrInvalidKeyRing
			}
		}
	}
	return nil
}

// Header is the header clients must use for the CSRF token.
const Header = "X-CSRF-Token"

// Guard holds the CSRF module's state and policy.
type Guard struct {
	keys     [][]byte
	clock    core.Clock
	cookie   string
	session  string
	path     string
	domain   string
	secure   bool
	sameSite http.SameSite
	prefix   string
	exempt   map[string]bool
	disabled bool
	logger   *slog.Logger
}

// New constructs a Guard from resolved configuration.
func New(keys [][]byte, clock core.Clock, cookieName, sessionCookieName, path, domain string, secure bool, sameSite http.SameSite, prefix string, exempt map[string]bool, disabled bool, logger *slog.Logger) *Guard {
	return &Guard{
		keys: keys, clock: clock, cookie: cookieName, session: sessionCookieName,
		path: path, domain: domain, secure: secure, sameSite: sameSite,
		prefix: prefix, exempt: exempt, disabled: disabled, logger: logger,
	}
}

// Issue returns a fresh signed CSRF token.
func (g *Guard) Issue() (string, error) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(nonce) + "." +
		strconv.FormatInt(g.clock.Now().Add(ttl).Unix(), 10)
	mac := hmac.New(sha256.New, g.keys[0])
	_, _ = mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Valid reports whether token is correctly signed and unexpired.
func (g *Guard) Valid(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || !g.clock.Now().Before(time.Unix(expires, 0)) {
		return false
	}
	payload := parts[0] + "." + parts[1]
	for _, key := range g.keys {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(payload))
		expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(parts[2]), []byte(expected)) {
			return true
		}
	}
	return false
}

// SetCookie writes the readable CSRF cookie. HttpOnly is deliberately false so
// JavaScript can copy the token into the header.
//
//nolint:gosec // G124: HttpOnly is deliberately false for the double-submit pattern.
func (g *Guard) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     g.cookie,
		Value:    token,
		Path:     g.path,
		Domain:   g.domain,
		Secure:   g.secure,
		HttpOnly: false,
		SameSite: g.sameSite,
		MaxAge:   int(ttl / time.Second),
	})
}

// IssueAndSetCookie issues a token and writes its cookie.
func (g *Guard) IssueAndSetCookie(w http.ResponseWriter) (string, error) {
	token, err := g.Issue()
	if err != nil {
		return "", err
	}
	g.SetCookie(w, token)
	return token, nil
}

func (g *Guard) isExempt(path string) bool {
	return g.exempt[strings.TrimPrefix(path, g.prefix+"/")]
}

func (g *Guard) sameOrigin(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		parsed, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(parsed.Host, r.Host) {
			return false
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if parsed.Scheme != "" && !strings.EqualFold(parsed.Scheme, scheme) &&
			(!strings.EqualFold(parsed.Scheme, "https") || scheme != "http") {
			return false
		}
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	return true
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// Guard rejects a state-changing request that carries a session cookie but no
// valid CSRF token. It reports whether the request was rejected.
func (g *Guard) Guard(w http.ResponseWriter, r *http.Request) bool {
	if g.disabled || !isStateChanging(r.Method) || g.isExempt(r.URL.Path) {
		return false
	}
	cookie, err := r.Cookie(g.session)
	if err != nil || cookie.Value == "" {
		return false
	}
	token := r.Header.Get(Header)
	csrfCookie, err := r.Cookie(g.cookie)
	if g.sameOrigin(r) && err == nil && token != "" && token == csrfCookie.Value && g.Valid(token) {
		return false
	}
	g.logger.Info("csrf_rejected", "at", g.clock.Now(), "path", r.URL.Path)
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf", "message": "cross-origin request rejected"})
	return true
}

// ServeToken implements GET /csrf-token.
func (g *Guard) ServeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token, err := g.IssueAndSetCookie(w)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func writeJSON(w http.ResponseWriter, status int, body map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
