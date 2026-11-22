// Package lastmethod signs and reads the optional Last sign-in method cookie.
package lastmethod

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

// Manager owns the cookie name, lifetime and signing key for Last sign-in method.
type Manager struct {
	key  []byte
	name string
	ttl  time.Duration
}

// New returns a Manager. key should be derived from an existing application secret.
func New(key []byte, name string, ttl time.Duration) *Manager {
	sum := sha256.Sum256(key)
	return &Manager{key: sum[:], name: name, ttl: ttl}
}

func (m *Manager) sign(value string) string {
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// SetCookie writes a signed, HttpOnly cookie carrying method.
func (m *Manager) SetCookie(w http.ResponseWriter, method string) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(method))
	value := encoded + "." + m.sign(encoded)
	http.SetCookie(w, &http.Cookie{
		Name: m.name, Value: value, Path: "/",
		MaxAge: int(m.ttl / time.Second), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// Method returns the signed method carried by the request, or empty.
func (m *Manager) Method(r *http.Request) string {
	cookie, err := r.Cookie(m.name)
	if err != nil {
		return ""
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(m.sign(parts[0]))) {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	return string(raw)
}

// Clear expires the cookie.
func (m *Manager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: m.name, Value: "", Path: "/", MaxAge: -1,
		Expires: time.Unix(1, 0), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}
