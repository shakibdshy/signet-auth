package signet

import (
	"context"
	"encoding/json"
	"errors"
	"net"
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
// endpoints under Config.PathPrefix. Only implemented endpoints do work; the
// remaining ones still return 501 until their phases arrive.
func (c *Client) Handler() http.Handler {
	prefix := strings.TrimRight(c.cfg.PathPrefix, "/")
	routes := make(map[string]string, len(authEndpoints))
	for _, endpoint := range authEndpoints {
		routes[prefix+"/"+endpoint] = endpoint
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch endpoint {
		case "signup":
			c.handleSignUp(w, r)
		case "signin":
			c.handleSignIn(w, r)
		case "signout":
			c.handleSignOut(w, r)
		default:
			http.Error(w, "signet: endpoint not implemented", http.StatusNotImplemented)
		}
	})
}

func (c *Client) handleSignUp(w http.ResponseWriter, r *http.Request) {
	var in SignUpInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	result, err := c.SignUp(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": result.User})
}

func (c *Client) handleSignIn(w http.ResponseWriter, r *http.Request) {
	var in SignInInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	result, err := c.SignIn(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":          result.User,
		"session_token": result.SessionToken,
	})
}

func (c *Client) handleSignOut(w http.ResponseWriter, r *http.Request) {
	var in SignOutInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	if err := c.SignOut(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrRateLimited):
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
	case errors.Is(err, ErrInvalidCredentials), errors.Is(err, ErrEmailNotVerified):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
	case errors.Is(err, ErrEmailAlreadyExists):
		writeError(w, http.StatusBadRequest, "email_exists", "email already registered")
	case errors.Is(err, ErrInvalidEmail), errors.Is(err, ErrPasswordTooShort),
		errors.Is(err, ErrPasswordTooLong):
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid input")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
