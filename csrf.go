package signet

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const csrfTTL = 12 * time.Hour

// csrfHeader is the header clients must use for the CSRF token.
const csrfHeader = "X-CSRF-Token"

type csrfPolicy struct {
	sessionCookieName string
	cookieName        string
	path              string
	domain            string
	secure            bool
	sameSite          http.SameSite
	prefix            string
}

// csrfGuard is the private CSRF module. Its interface is small: guard a
// request, issue a token and set its cookie, and serve the token endpoint.
// Signing, validation, same-origin checks and exemptions stay behind it.
type csrfGuard struct {
	key      []byte
	clock    Clock
	policy   csrfPolicy
	exempt   map[string]bool
	disabled bool
	logger   *slog.Logger
}

func newCSRFGuard(cfg Config, exempt map[string]bool) *csrfGuard {
	name := "signet_csrf"
	sessionName := cfg.Cookie.Name
	if cfg.Cookie.Secure && cfg.Cookie.Path == "/" && cfg.Cookie.Domain == "" {
		name = "__Host-" + name
		sessionName = "__Host-" + sessionName
	}
	return &csrfGuard{
		key:   cfg.CSRFKey,
		clock: cfg.Clock,
		policy: csrfPolicy{
			sessionCookieName: sessionName,
			cookieName:        name,
			path:              cfg.Cookie.Path,
			domain:            cfg.Cookie.Domain,
			secure:            cfg.Cookie.Secure,
			sameSite:          cfg.Cookie.SameSite,
			prefix:            strings.TrimRight(cfg.PathPrefix, "/"),
		},
		exempt:   exempt,
		disabled: cfg.InsecureDisableCSRF,
		logger:   cfg.Logger,
	}
}

func (g *csrfGuard) issue() (string, error) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(nonce) + "." +
		strconv.FormatInt(g.clock.Now().Add(csrfTTL).Unix(), 10)
	mac := hmac.New(sha256.New, g.key)
	_, _ = mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (g *csrfGuard) valid(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || !g.clock.Now().Before(time.Unix(expires, 0)) {
		return false
	}
	mac := hmac.New(sha256.New, g.key)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(parts[2]), []byte(expected))
}

// SetCookie writes the readable CSRF cookie. HttpOnly is deliberately false so
// JavaScript can copy the token into the header.
//
//nolint:gosec // G124: HttpOnly is deliberately false for the double-submit pattern.
func (g *csrfGuard) setCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     g.policy.cookieName,
		Value:    token,
		Path:     g.policy.path,
		Domain:   g.policy.domain,
		Secure:   g.policy.secure,
		HttpOnly: false,
		SameSite: g.policy.sameSite,
		MaxAge:   int(csrfTTL / time.Second),
	})
}

func (g *csrfGuard) IssueAndSetCookie(w http.ResponseWriter) (string, error) {
	token, err := g.issue()
	if err != nil {
		return "", err
	}
	g.setCookie(w, token)
	return token, nil
}

func (g *csrfGuard) isExempt(path string) bool {
	name := strings.TrimPrefix(path, g.policy.prefix+"/")
	return g.exempt[name]
}

func (g *csrfGuard) sameOrigin(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		parsed, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(parsed.Host, r.Host) {
			return false
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		// A TLS-terminating proxy presents an http request to us while the
		// browser sent an https Origin; accepting that direction stays safe
		// because the host must still match exactly.
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

func (g *csrfGuard) Guard(w http.ResponseWriter, r *http.Request) bool {
	if g.disabled || !isStateChanging(r.Method) || g.isExempt(r.URL.Path) {
		return false
	}
	cookie, err := r.Cookie(g.policy.sessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	token := r.Header.Get(csrfHeader)
	csrfCookie, err := r.Cookie(g.policy.cookieName)
	if g.sameOrigin(r) && err == nil && token != "" && token == csrfCookie.Value && g.valid(token) {
		return false
	}
	g.logger.Info("csrf_rejected", "at", g.clock.Now(), "path", r.URL.Path)
	writeError(w, http.StatusForbidden, "csrf", "cross-origin request rejected")
	return true
}

func (g *csrfGuard) ServeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token, err := g.IssueAndSetCookie(w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}
