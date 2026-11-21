// Package httpapi implements Signet's net/http adapter layer.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/shakibdshy/signet/internal/core"
)

// API is the surface the HTTP adapter needs from the root Client.
type API interface {
	SignUp(context.Context, core.SignUpInput) (*core.SignUpResult, error)
	SignIn(context.Context, core.SignInInput) (*core.SignInResult, error)
	SignOut(context.Context, core.SignOutInput) error
	ChangePassword(context.Context, core.ChangePasswordInput) error
	RequestEmailChange(context.Context, core.ChangeEmailInput) error
	VerifyEmailChange(context.Context, core.VerifyEmailChangeInput) error
	ListSessions(context.Context, core.ListSessionsInput) (*core.ListSessionsResult, error)
	RevokeSession(context.Context, core.RevokeSessionInput) error
	RevokeAllSessions(context.Context, core.RevokeAllSessionsInput) error
	ExchangeToken(context.Context, core.TokenInput) (*core.TokenPair, error)
	SendVerification(context.Context, core.SendVerificationInput) error
	VerifyEmail(context.Context, core.VerifyEmailInput) error
	SendPasswordReset(context.Context, core.SendPasswordResetInput) error
	ResetPassword(context.Context, core.ResetPasswordInput) error
	OAuthStart(context.Context, core.OAuthStartInput) (*core.OAuthStartResult, error)
	OAuthCallback(context.Context, core.OAuthCallbackInput) (*core.OAuthCallbackResult, error)
	Authenticate(http.ResponseWriter, *http.Request, bool) (*core.User, bool)
	CurrentSession(*http.Request) (*core.Session, error)
	CSRFGuard(http.ResponseWriter, *http.Request) bool
	ServeCSRFToken(http.ResponseWriter, *http.Request)
	SetSessionCookies(http.ResponseWriter, string) (string, error)
	CookieName() string
	NewSessionCookie(string, bool) *http.Cookie
	ClearSessionCookie(http.ResponseWriter)
}

// Handler serves the authentication endpoints using an API adapter.
type Handler struct {
	api    API
	prefix string
}

// New returns a Handler for api under prefix.
func New(api API, prefix string) *Handler { return &Handler{api: api, prefix: prefix} }

// Endpoint names an auth endpoint and whether it is anonymous.
type Endpoint struct {
	Name      string
	Anonymous bool
}

// Endpoints is the route table.
var Endpoints = []Endpoint{
	{Name: "signup", Anonymous: true},
	{Name: "signin", Anonymous: true},
	{Name: "signout"},
	{Name: "sessions"},
	{Name: "session"},
	{Name: "token", Anonymous: true},
	{Name: "send-verification"},
	{Name: "verify-email"},
	{Name: "send-password-reset"},
	{Name: "reset-password"},
	{Name: "change-password"},
	{Name: "change-email"},
	{Name: "verify-change-email"},
	{Name: "oauth/start", Anonymous: true},
	{Name: "oauth/callback", Anonymous: true},
	{Name: "csrf-token", Anonymous: true},
}

// Handler returns a plain http.Handler serving Signet's authentication
// endpoints under Config.PathPrefix.
func (h *Handler) Handler() http.Handler {
	prefix := strings.TrimRight(h.prefix, "/")
	routes := make(map[string]string, len(Endpoints))
	for _, endpoint := range Endpoints {
		routes[prefix+"/"+endpoint.Name] = endpoint.Name
	}
	base := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch endpoint {
		case "signup":
			h.handleSignUp(w, r)
		case "signin":
			h.handleSignIn(w, r)
		case "signout":
			h.handleSignOut(w, r)
		case "sessions":
			h.handleSessions(w, r)
		case "session":
			h.handleCurrentSession(w, r)
		case "token":
			h.handleToken(w, r)
		case "send-verification":
			h.handleSendVerification(w, r)
		case "verify-email":
			h.handleVerifyEmail(w, r)
		case "send-password-reset":
			h.handleSendPasswordReset(w, r)
		case "reset-password":
			h.handleResetPassword(w, r)
		case "change-password":
			h.handleChangePassword(w, r)
		case "change-email":
			h.handleChangeEmail(w, r)
		case "verify-change-email":
			h.handleVerifyEmailChange(w, r)
		case "oauth/start":
			h.handleOAuthStart(w, r)
		case "oauth/callback":
			h.handleOAuthCallback(w, r)
		case "csrf-token":
			h.api.ServeCSRFToken(w, r)
		default:
			http.Error(w, "signet: endpoint not implemented", http.StatusNotImplemented)
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.api.CSRFGuard(w, r) {
			return
		}
		base.ServeHTTP(w, r)
	})
}

func (h *Handler) handleSignUp(w http.ResponseWriter, r *http.Request) {
	var in core.SignUpInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	result, err := h.api.SignUp(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": result.User})
}

func (h *Handler) handleSignIn(w http.ResponseWriter, r *http.Request) {
	var in core.SignInInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	result, err := h.api.SignIn(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	csrfToken, err := h.api.SetSessionCookies(w, result.SessionToken)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":          result.User,
		"session_token": result.SessionToken,
		"csrf_token":    csrfToken,
	})
}

func (h *Handler) handleSignOut(w http.ResponseWriter, r *http.Request) {
	var in core.SignOutInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	if err := h.api.SignOut(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	h.api.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleSessions(w http.ResponseWriter, r *http.Request) {
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		result, err := h.api.ListSessions(r.Context(), core.ListSessionsInput{UserID: user.ID})
		if err != nil {
			writeAuthError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessions": result.Sessions})
	case http.MethodDelete:
		if err := h.api.RevokeAllSessions(r.Context(), core.RevokeAllSessionsInput{UserID: user.ID}); err != nil {
			writeAuthError(w, err)
			return
		}
		h.api.ClearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleCurrentSession(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.api.Authenticate(w, r, true); !ok {
		return
	}
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	session, err := h.api.CurrentSession(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if err := h.api.RevokeSession(r.Context(), core.RevokeSessionInput{SessionID: session.ID}); err != nil {
		writeAuthError(w, err)
		return
	}
	h.api.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.TokenInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	pair, err := h.api.ExchangeToken(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

func (h *Handler) handleSendVerification(w http.ResponseWriter, r *http.Request) {
	var in core.SendVerificationInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	if err := h.api.SendVerification(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var in core.VerifyEmailInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	if err := h.api.VerifyEmail(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleSendPasswordReset(w http.ResponseWriter, r *http.Request) {
	var in core.SendPasswordResetInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	if err := h.api.SendPasswordReset(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var in core.ResetPasswordInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	if err := h.api.ResetPassword(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.ChangePasswordInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.UserID = user.ID
	in.RateLimitKey = clientIP(r)
	if err := h.api.ChangePassword(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleChangeEmail(w http.ResponseWriter, r *http.Request) {
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	var in core.ChangeEmailInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.UserID = user.ID
	in.RateLimitKey = clientIP(r)
	if err := h.api.RequestEmailChange(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleVerifyEmailChange(w http.ResponseWriter, r *http.Request) {
	var in core.VerifyEmailChangeInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	if err := h.api.VerifyEmailChange(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.OAuthStartInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = clientIP(r)
	result, err := h.api.OAuthStart(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	in := core.OAuthCallbackInput{
		Code:         r.URL.Query().Get("code"),
		State:        r.URL.Query().Get("state"),
		RateLimitKey: clientIP(r),
	}
	result, err := h.api.OAuthCallback(r.Context(), in)
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
	} else if _, err := h.api.SetSessionCookies(w, result.SessionToken); err != nil {
		writeAuthError(w, err)
		return
	}
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func writeAuthError(w http.ResponseWriter, err error) {
	for _, spec := range ContractFor().Errors {
		if spec.Sentinel == nil {
			if spec.Code == "internal_error" {
				writeError(w, spec.Status, spec.Code, spec.Message)
				return
			}
			continue
		}
		if errors.Is(err, spec.Sentinel) {
			writeError(w, spec.Status, spec.Code, spec.Message)
			return
		}
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
