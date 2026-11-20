package signet

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const csrfTTL = 12 * time.Hour

// csrfHeader is the header clients must use for the CSRF token.
const csrfHeader = "X-CSRF-Token"

func (c *Client) csrfCookieName() string {
	if c.useHostPrefix() {
		return "__Host-signet_csrf"
	}
	return "signet_csrf"
}

func (c *Client) issueCSRFToken() (string, error) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(nonce) + "." +
		strconv.FormatInt(c.cfg.Clock.Now().Add(csrfTTL).Unix(), 10)
	mac := hmac.New(sha256.New, c.cfg.CSRFKey)
	_, _ = mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (c *Client) validCSRFToken(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || !c.cfg.Clock.Now().Before(time.Unix(expires, 0)) {
		return false
	}
	mac := hmac.New(sha256.New, c.cfg.CSRFKey)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(parts[2]), []byte(expected))
}

//nolint:gosec // G124: HttpOnly is deliberately false so JavaScript can read the token.
func (c *Client) setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.csrfCookieName(),
		Value:    token,
		Path:     c.cfg.Cookie.Path,
		Domain:   c.cfg.Cookie.Domain,
		Secure:   c.cfg.Cookie.Secure,
		HttpOnly: false,
		SameSite: c.cfg.Cookie.SameSite,
		MaxAge:   int(csrfTTL / time.Second),
	})
}

func (c *Client) setSessionAndCSRFCookies(w http.ResponseWriter, sessionToken string) (string, error) {
	if c.cfg.JWTOnly {
		return "", nil
	}
	csrfToken, err := c.issueCSRFToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, c.sessionCookie(sessionToken, false))
	c.setCSRFCookie(w, csrfToken)
	return csrfToken, nil
}

func (c *Client) csrfExempt(path string) bool {
	prefix := strings.TrimRight(c.cfg.PathPrefix, "/")
	name := strings.TrimPrefix(path, prefix+"/")
	for _, endpoint := range authEndpoints {
		if endpoint.anonymous && endpoint.name == name {
			return true
		}
	}
	return false
}
