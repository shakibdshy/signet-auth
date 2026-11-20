package signet

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var authEndpoints = []string{
	"signup",
	"signin",
	"signout",
	"sessions",
	"session",
	"token",
	"send-verification",
	"verify-email",
	"send-password-reset",
	"reset-password",
	"oauth/start",
	"oauth/callback",
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
	base := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		case "sessions":
			c.handleSessions(w, r)
		case "session":
			c.handleCurrentSession(w, r)
		case "token":
			c.handleToken(w, r)
		case "send-verification":
			c.handleSendVerification(w, r)
		case "verify-email":
			c.handleVerifyEmail(w, r)
		case "send-password-reset":
			c.handleSendPasswordReset(w, r)
		case "reset-password":
			c.handleResetPassword(w, r)
		case "oauth/start":
			c.handleOAuthStart(w, r)
		case "oauth/callback":
			c.handleOAuthCallback(w, r)
		default:
			http.Error(w, "signet: endpoint not implemented", http.StatusNotImplemented)
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.csrfRejected(w, r) {
			return
		}
		base.ServeHTTP(w, r)
	})
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func (c *Client) hasSessionCookie(r *http.Request) bool {
	cookie, err := r.Cookie(c.cookieName())
	return err == nil && cookie.Value != ""
}

func (c *Client) csrfRejected(w http.ResponseWriter, r *http.Request) bool {
	if c.cfg.InsecureDisableCSRF || !isStateChanging(r.Method) || !c.hasSessionCookie(r) || c.isSameOrigin(r) {
		return false
	}
	c.logInfo("csrf_rejected", "path", r.URL.Path)
	writeError(w, http.StatusForbidden, "csrf", "cross-origin request rejected")
	return true
}

func (c *Client) isSameOrigin(r *http.Request) bool {
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
	http.SetCookie(w, c.sessionCookie(result.SessionToken, false))
	writeJSON(w, http.StatusOK, map[string]any{
		"user":          result.User,
		"session_token": result.SessionToken,
	})
}

func (c *Client) cookieName() string {
	if c.cfg.Cookie.Secure && c.cfg.Cookie.Path == "/" && c.cfg.Cookie.Domain == "" {
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
	http.SetCookie(w, c.sessionCookie("", true))
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
	c.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (c *Client) handleSessions(w http.ResponseWriter, r *http.Request) {
	user, ok := c.authenticate(w, r, true)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		result, err := c.ListSessions(r.Context(), ListSessionsInput{UserID: user.ID})
		if err != nil {
			writeAuthError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessions": result.Sessions})
	case http.MethodDelete:
		if err := c.RevokeAllSessions(r.Context(), RevokeAllSessionsInput{UserID: user.ID}); err != nil {
			writeAuthError(w, err)
			return
		}
		c.clearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *Client) handleCurrentSession(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.authenticate(w, r, true); !ok {
		return
	}
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	session, err := c.currentSession(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if err := c.RevokeSession(r.Context(), RevokeSessionInput{SessionID: session.ID}); err != nil {
		writeAuthError(w, err)
		return
	}
	c.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (c *Client) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in TokenInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	pair, err := c.ExchangeToken(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

func (c *Client) handleSendVerification(w http.ResponseWriter, r *http.Request) {
	var in SendVerificationInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	if err := c.SendVerification(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (c *Client) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var in VerifyEmailInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	if err := c.VerifyEmail(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (c *Client) handleSendPasswordReset(w http.ResponseWriter, r *http.Request) {
	var in SendPasswordResetInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	if err := c.SendPasswordReset(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (c *Client) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var in ResetPasswordInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	if err := c.ResetPassword(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (c *Client) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in OAuthStartInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	result, err := c.OAuthStart(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (c *Client) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	in := OAuthCallbackInput{
		Code:         r.URL.Query().Get("code"),
		State:        r.URL.Query().Get("state"),
		RateLimitKey: clientIP(r),
	}
	result, err := c.OAuthCallback(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	target, err := url.Parse(result.Redirect)
	if err != nil {
		target = &url.URL{Path: "/"}
	}
	if result.LinkToken != "" {
		query := target.Query()
		query.Set("link_token", result.LinkToken)
		target.RawQuery = query.Encode()
	} else {
		http.SetCookie(w, c.sessionCookie(result.SessionToken, false))
	}
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrRateLimited):
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
	case errors.Is(err, ErrTokenInvalid), errors.Is(err, ErrTokenExpired), errors.Is(err, ErrRefreshReuse):
		writeError(w, http.StatusUnauthorized, "invalid_token", "invalid token")
	case errors.Is(err, ErrEmailNotVerified):
		writeError(w, http.StatusForbidden, "email_not_verified", "email not verified")
	case errors.Is(err, ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
	case errors.Is(err, ErrJWTDisabled), errors.Is(err, ErrOAuthDisabled), errors.Is(err, ErrOAuthProviderNotFound):
		writeError(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, ErrOAuthRedirectNotAllowed), errors.Is(err, ErrOAuthInvalidState):
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request")
	case errors.Is(err, ErrOAuthEmailNotVerified):
		writeError(w, http.StatusForbidden, "oauth_email_not_verified", "email not verified by provider")
	case errors.Is(err, ErrOAuthAccountConflict):
		writeError(w, http.StatusConflict, "oauth_account_conflict", "provider account belongs to another user")
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

// UserFromContext returns the authenticated User carried by a request context,
// and reports whether one was present.
func UserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(userContextKey{}).(*User)
	return user, ok
}
