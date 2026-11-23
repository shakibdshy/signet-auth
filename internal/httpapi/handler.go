// Package httpapi implements Signet's net/http adapter layer.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/shakibdshy/signet/internal/core"
)

// API is the surface the HTTP adapter needs from the root Client.
type API interface {
	SignUp(context.Context, core.SignUpInput) (*core.SignUpResult, error)
	SignIn(context.Context, core.SignInInput) (*core.SignInResult, error)
	EnableTwoFactor(context.Context, core.EnableTwoFactorInput) (*core.EnableTwoFactorResult, error)
	VerifyTwoFactor(context.Context, core.VerifyTwoFactorInput) (*core.SignInResult, error)
	DisableTwoFactor(context.Context, core.DisableTwoFactorInput) error
	RegenerateBackupCodes(context.Context, core.RegenerateBackupCodesInput) (*core.RegenerateBackupCodesResult, error)
	SendMagicLink(context.Context, core.SendMagicLinkInput) error
	VerifyMagicLink(context.Context, core.VerifyMagicLinkInput) (*core.SignInResult, error)
	SendEmailOTP(context.Context, core.SendEmailOTPInput) error
	VerifyEmailOTP(context.Context, core.VerifyEmailOTPInput) (*core.SignInResult, error)
	SignOut(context.Context, core.SignOutInput) error
	ChangePassword(context.Context, core.ChangePasswordInput) error
	RequestEmailChange(context.Context, core.ChangeEmailInput) error
	VerifyEmailChange(context.Context, core.VerifyEmailChangeInput) error
	RequestUserDeletion(context.Context, core.RequestDeleteUserInput) error
	DeleteUser(context.Context, core.ConfirmDeleteUserInput) error
	ListAccounts(context.Context, core.ListAccountsInput) (*core.ListAccountsResult, error)
	UnlinkAccount(context.Context, core.UnlinkAccountInput) error
	SessionTokenFromRequest(*http.Request) string
	VerifyAPIKey(context.Context, string) (*core.Principal, error)
	ListAPIKeys(context.Context, core.ListAPIKeysInput) (*core.ListAPIKeysResult, error)
	CreateAPIKey(context.Context, core.CreateAPIKeyInput) (*core.CreateAPIKeyResult, error)
	RevokeAPIKey(context.Context, core.RevokeAPIKeyInput) error
	APIKeyProtectedEndpoints() []string
	SetPrincipal(*http.Request, *core.Principal) *http.Request
	LastSignInMethod(*http.Request) string
	SetLastMethodCookie(http.ResponseWriter, string)
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
	api     API
	prefix  string
	trusted []netip.Prefix
}

// New returns a Handler for api under prefix.
func New(api API, prefix string, trusted []netip.Prefix) *Handler {
	return &Handler{api: api, prefix: prefix, trusted: trusted}
}

// Endpoint names an auth endpoint and whether it is anonymous.
type Endpoint struct {
	Name      string
	Anonymous bool
}

// Endpoints is the route table.
var Endpoints = []Endpoint{
	{Name: "signup", Anonymous: true},
	{Name: "signin", Anonymous: true},
	{Name: "send-magic-link", Anonymous: true},
	{Name: "verify-magic-link", Anonymous: true},
	{Name: "send-otp", Anonymous: true},
	{Name: "verify-otp", Anonymous: true},
	{Name: "signout"},
	{Name: "enable-two-factor"},
	{Name: "verify-two-factor", Anonymous: true},
	{Name: "disable-two-factor"},
	{Name: "regenerate-backup-codes"},
	{Name: "last-sign-in-method", Anonymous: true},
	{Name: "accounts"},
	{Name: "unlink-account"},
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
	{Name: "request-account-deletion"},
	{Name: "confirm-account-deletion"},
	{Name: "oauth/start", Anonymous: true},
	{Name: "oauth/callback", Anonymous: true},
	{Name: "csrf-token", Anonymous: true},
	{Name: "api-keys", Anonymous: true},
	{Name: "verify-api-key", Anonymous: true},
	{Name: "revoke-api-key"},
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
		case "send-magic-link":
			h.handleSendMagicLink(w, r)
		case "verify-magic-link":
			h.handleVerifyMagicLink(w, r)
		case "send-otp":
			h.handleSendOTP(w, r)
		case "verify-otp":
			h.handleVerifyOTP(w, r)
		case "signout":
			h.handleSignOut(w, r)
		case "enable-two-factor":
			h.handleEnableTwoFactor(w, r)
		case "verify-two-factor":
			h.handleVerifyTwoFactor(w, r)
		case "disable-two-factor":
			h.handleDisableTwoFactor(w, r)
		case "regenerate-backup-codes":
			h.handleRegenerateBackupCodes(w, r)
		case "last-sign-in-method":
			h.handleLastSignInMethod(w, r)
		case "accounts":
			h.handleAccounts(w, r)
		case "unlink-account":
			h.handleUnlinkAccount(w, r)
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
		case "request-account-deletion":
			h.handleRequestAccountDeletion(w, r)
		case "confirm-account-deletion":
			h.handleConfirmAccountDeletion(w, r)
		case "oauth/start":
			h.handleOAuthStart(w, r)
		case "oauth/callback":
			h.handleOAuthCallback(w, r)
		case "api-keys":
			h.handleAPIKeys(w, r)
		case "verify-api-key":
			h.handleVerifyAPIKey(w, r)
		case "revoke-api-key":
			h.handleRevokeAPIKey(w, r)
		case "csrf-token":
			h.api.ServeCSRFToken(w, r)
		default:
			http.Error(w, "signet: endpoint not implemented", http.StatusNotImplemented)
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.api.APIKeyProtectedEndpoints() != nil {
			prefix := strings.TrimRight(h.prefix, "/") + "/"
			name := strings.TrimPrefix(r.URL.Path, prefix)
			for _, protected := range h.api.APIKeyProtectedEndpoints() {
				if "/"+protected == r.URL.Path || protected == name {
					raw := r.Header.Get("X-API-Key")
					if raw == "" {
						writeError(w, http.StatusUnauthorized, "invalid_token", "api key required")
						return
					}
					principal, err := h.api.VerifyAPIKey(r.Context(), raw)
					if err != nil {
						writeAuthError(w, err)
						return
					}
					r = h.api.SetPrincipal(r, principal)
					base.ServeHTTP(w, r)
					return
				}
			}
		}
		if h.api.CSRFGuard(w, r) {
			return
		}
		base.ServeHTTP(w, r)
	})
}

func (h *Handler) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		result, err := h.api.ListAPIKeys(r.Context(), core.ListAPIKeysInput{
			OwnerUserID: user.ID, SessionToken: h.api.SessionTokenFromRequest(r),
		})
		if err != nil {
			writeAuthError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case http.MethodPost:
		var in core.CreateAPIKeyInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
			return
		}
		in.OwnerUserID = user.ID
		in.SessionToken = h.api.SessionTokenFromRequest(r)
		result, err := h.api.CreateAPIKey(r.Context(), in)
		if err != nil {
			writeAuthError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	var in core.RevokeAPIKeyInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.OwnerUserID = user.ID
	in.SessionToken = h.api.SessionTokenFromRequest(r)
	if err := h.api.RevokeAPIKey(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleVerifyAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	principal, err := h.api.VerifyAPIKey(r.Context(), r.Header.Get("X-API-Key"))
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, principal)
}

func (h *Handler) handleSignUp(w http.ResponseWriter, r *http.Request) {
	var in core.SignUpInput
	in.CaptchaToken = r.Header.Get("X-Captcha-Response")
	in.CaptchaRemoteIP = h.clientIP(r)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = h.clientIP(r)
	result, err := h.api.SignUp(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": result.User})
}

func (h *Handler) handleSignIn(w http.ResponseWriter, r *http.Request) {
	var in core.SignInInput
	in.CaptchaToken = r.Header.Get("X-Captcha-Response")
	in.CaptchaRemoteIP = h.clientIP(r)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = h.clientIP(r)
	result, err := h.api.SignIn(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if result.TwoFactorChallenge != "" {
		h.api.SetLastMethodCookie(w, result.LastSignInMethod)
		writeJSON(w, http.StatusOK, map[string]any{
			"user": result.User, "two_factor_challenge": result.TwoFactorChallenge,
			"error": "two_factor_required",
		})
		return
	}
	csrfToken, err := h.api.SetSessionCookies(w, result.SessionToken)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	h.api.SetLastMethodCookie(w, result.LastSignInMethod)
	writeJSON(w, http.StatusOK, map[string]any{
		"user":          result.User,
		"session_token": result.SessionToken,
		"csrf_token":    csrfToken,
	})
}

func (h *Handler) handleSendMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.SendMagicLinkInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = h.clientIP(r)
	if err := h.api.SendMagicLink(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleVerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	in := core.VerifyMagicLinkInput{
		Token:        r.URL.Query().Get("token"),
		CallbackURL:  r.URL.Query().Get("callback_url"),
		RateLimitKey: h.clientIP(r),
	}
	result, err := h.api.VerifyMagicLink(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if _, err := h.api.SetSessionCookies(w, result.SessionToken); err != nil {
		writeAuthError(w, err)
		return
	}
	h.api.SetLastMethodCookie(w, result.LastSignInMethod)
	callback := in.CallbackURL
	if callback == "" {
		// The emailed link carries the callback inside its proof; the query
		// parameter is optional and, when present, must match the embedded one.
		callback = result.CallbackURL
	}
	if callback != "" {
		http.Redirect(w, r, callback, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user": result.User, "session_token": result.SessionToken,
	})
}

func (h *Handler) handleSendOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.SendEmailOTPInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = h.clientIP(r)
	if err := h.api.SendEmailOTP(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleVerifyOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.VerifyEmailOTPInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = h.clientIP(r)
	result, err := h.api.VerifyEmailOTP(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if _, err := h.api.SetSessionCookies(w, result.SessionToken); err != nil {
		writeAuthError(w, err)
		return
	}
	h.api.SetLastMethodCookie(w, result.LastSignInMethod)
	writeJSON(w, http.StatusOK, map[string]any{
		"user": result.User, "session_token": result.SessionToken,
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

func (h *Handler) handleEnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	var in core.EnableTwoFactorInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.UserID = user.ID
	in.RateLimitKey = h.clientIP(r)
	result, err := h.api.EnableTwoFactor(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleVerifyTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.VerifyTwoFactorInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = h.clientIP(r)
	result, err := h.api.VerifyTwoFactor(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if _, err := h.api.SetSessionCookies(w, result.SessionToken); err != nil {
		writeAuthError(w, err)
		return
	}
	h.api.SetLastMethodCookie(w, result.LastSignInMethod)
	writeJSON(w, http.StatusOK, map[string]any{"user": result.User, "session_token": result.SessionToken})
}

func (h *Handler) handleDisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	var in core.DisableTwoFactorInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.UserID = user.ID
	in.RateLimitKey = h.clientIP(r)
	if err := h.api.DisableTwoFactor(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleRegenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	var in core.RegenerateBackupCodesInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.UserID = user.ID
	in.SessionToken = h.api.SessionTokenFromRequest(r)
	in.RateLimitKey = h.clientIP(r)
	result, err := h.api.RegenerateBackupCodes(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleLastSignInMethod(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"method": h.api.LastSignInMethod(r)})
}

func (h *Handler) handleAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	result, err := h.api.ListAccounts(r.Context(), core.ListAccountsInput{UserID: user.ID})
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": result.Accounts})
}

func (h *Handler) handleUnlinkAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	var in core.UnlinkAccountInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.UserID = user.ID
	in.SessionToken = h.api.SessionTokenFromRequest(r)
	in.RateLimitKey = h.clientIP(r)
	if err := h.api.UnlinkAccount(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
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
	in.RateLimitKey = h.clientIP(r)
	pair, err := h.api.ExchangeToken(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if pair.TwoFactorChallenge != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"two_factor_challenge": pair.TwoFactorChallenge, "error": "two_factor_required",
		})
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
	in.RateLimitKey = h.clientIP(r)
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
	in.RateLimitKey = h.clientIP(r)
	if err := h.api.VerifyEmail(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleSendPasswordReset(w http.ResponseWriter, r *http.Request) {
	var in core.SendPasswordResetInput
	in.CaptchaToken = r.Header.Get("X-Captcha-Response")
	in.CaptchaRemoteIP = h.clientIP(r)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = h.clientIP(r)
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
	in.RateLimitKey = h.clientIP(r)
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
	in.RateLimitKey = h.clientIP(r)
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
	in.RateLimitKey = h.clientIP(r)
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
	in.RateLimitKey = h.clientIP(r)
	if err := h.api.VerifyEmailChange(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleRequestAccountDeletion(w http.ResponseWriter, r *http.Request) {
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	in := core.RequestDeleteUserInput{UserID: user.ID, RateLimitKey: h.clientIP(r)}
	if err := h.api.RequestUserDeletion(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleConfirmAccountDeletion(w http.ResponseWriter, r *http.Request) {
	var in core.ConfirmDeleteUserInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.RateLimitKey = h.clientIP(r)
	if err := h.api.DeleteUser(r.Context(), in); err != nil {
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
	in.RateLimitKey = h.clientIP(r)
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
		RateLimitKey: h.clientIP(r),
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
	h.api.SetLastMethodCookie(w, result.LastSignInMethod)
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

func (h *Handler) clientIP(r *http.Request) string {
	return resolveClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), h.trusted)
}
