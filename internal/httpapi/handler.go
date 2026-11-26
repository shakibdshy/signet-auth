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

	"github.com/shakibdshy/signet-auth/internal/core"
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
	SetActiveOrganization(context.Context, core.SetActiveOrganizationInput) error
	SetActiveOrganizationCookie(http.ResponseWriter, string)
	ActiveOrganizationFromRequest(*http.Request) *core.ActiveOrganization
	ClearActiveOrganizationCookie(http.ResponseWriter)
	CreateOrganization(context.Context, core.CreateOrganizationInput) (*core.CreateOrganizationResult, error)
	ListOrganizations(context.Context, core.ListOrganizationsInput) (*core.ListOrganizationsResult, error)
	AddOrganizationMember(context.Context, core.AddOrganizationMemberInput) error
	ListOrganizationMembers(context.Context, string, string, string) (*core.ListOrganizationMembersResult, error)
	RemoveOrganizationMember(context.Context, string, string, string, string) error
	SetOrganizationMemberRole(context.Context, string, string, string, string, string) error
	AdminListUsers(context.Context, core.AdminListUsersInput) (*core.AdminListUsersResult, error)
	AdminListUserSessions(context.Context, string, string, string) (*core.ListSessionsResult, error)
	AdminRevokeUserSession(context.Context, string, string, string) error
	BanUser(context.Context, core.BanUserInput) error
	UnbanUser(context.Context, core.UnbanUserInput) error
	AdminSetUserRole(context.Context, core.AdminSetUserRoleInput) error
	ImpersonateUser(context.Context, core.ImpersonateUserInput) (*core.ImpersonationResult, error)
	StopImpersonating(context.Context, core.StopImpersonatingInput) (string, error)
	SetImpersonationCookie(http.ResponseWriter, string, string)
	ClearImpersonationCookie(http.ResponseWriter)
	ImpersonationFromRequest(*http.Request) (string, string)
	IsImpersonating(*http.Request) bool
	AdminActor(*http.Request, string) string
	BeginPasskeyRegistration(context.Context, core.PasskeyRegistrationInput) (*core.PasskeyCeremonyResult, error)
	FinishPasskeyRegistration(context.Context, core.PasskeyFinishInput) error
	BeginPasskeySignIn(context.Context) (*core.PasskeyCeremonyResult, error)
	FinishPasskeySignIn(context.Context, core.PasskeyFinishSignInInput) (*core.SignInResult, error)
	ListPasskeys(context.Context, core.PasskeyListInput) (*core.PasskeyListResult, error)
	DeletePasskey(context.Context, core.PasskeyDeleteInput) error
	OAuthAuthorize(context.Context, core.OAuthAuthorizeInput) (*core.OAuthAuthorizeResult, error)
	OAuthExchange(context.Context, core.OAuthTokenInput) (*core.OAuthTokenResult, error)
	OAuthRefresh(context.Context, core.OAuthTokenInput) (*core.OAuthTokenResult, error)
	BeginDeviceAuthorization(context.Context, core.DeviceAuthorizeInput) (*core.DeviceAuthorizeResult, error)
	ApproveDeviceAuthorization(context.Context, core.DeviceApproveInput) error
	ExchangeDeviceAuthorization(context.Context, string) (*core.OAuthTokenResult, error)
	SCIMHandler() http.Handler
	CreateSSOConnection(context.Context, core.CreateSSOConnectionInput) (*core.SSOConnectionInfo, error)
	ListSSOConnections(context.Context, string) ([]*core.SSOConnectionInfo, error)
	DeleteSSOConnection(context.Context, string, string) error
	StartSSOSignIn(context.Context, core.SSOStartInput) (*core.SSOStartResult, error)
	CompleteSSOSignIn(context.Context, core.SSOCallbackInput) (*core.SSOCallbackResult, error)
	StartSAMLSignIn(context.Context, core.SAMLStartInput) (*core.SAMLStartResult, error)
	CompleteSAMLSignIn(context.Context, string, *http.Request) (*core.SAMLACSResult, error)
	LastSignInMethod(*http.Request) string
	SetLastMethodCookie(http.ResponseWriter, string)
	ListSessions(context.Context, core.ListSessionsInput) (*core.ListSessionsResult, error)
	RevokeSession(context.Context, core.RevokeSessionInput) error
	RevokeAllSessions(context.Context, core.RevokeAllSessionsInput) error
	ExchangeToken(context.Context, core.TokenInput) (*core.TokenPair, error)
	SendVerification(context.Context, core.SendVerificationInput) error
	VerifyEmail(context.Context, core.VerifyEmailInput) error
	VerifyEmailAndSignIn(context.Context, core.VerifyEmailInput) (*core.VerifyEmailAndSignInResult, error)
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
	{Name: "set-active-organization"},
	{Name: "active-organization", Anonymous: true},
	{Name: "organizations"},
	{Name: "organization-members"},
	{Name: "organization-members/add"},
	{Name: "organization-members/remove"},
	{Name: "organization-members/role"},
	{Name: "clear-active-organization"},
	{Name: "admin-users"},
	{Name: "admin-users/role"},
	{Name: "admin-users/ban"},
	{Name: "admin-users/unban"},
	{Name: "admin-user-sessions"},
	{Name: "admin-user-sessions/revoke"},
	{Name: "impersonate"},
	{Name: "stop-impersonating"},
	{Name: "passkeys/register-begin"},
	{Name: "passkeys/register-finish"},
	{Name: "passkeys/signin-begin", Anonymous: true},
	{Name: "passkeys/signin-finish", Anonymous: true},
	{Name: "passkeys"},
	{Name: "passkeys/delete"},
	{Name: "oauth/authorize"},
	{Name: "oauth/token", Anonymous: true},
	{Name: "oauth/device/authorize", Anonymous: true},
	{Name: "oauth/device/token", Anonymous: true},
	{Name: "oauth/device/approve"},
	{Name: "sso/start", Anonymous: true},
	{Name: "sso/callback", Anonymous: true},
	{Name: "saml/start", Anonymous: true},
	{Name: "saml/acs", Anonymous: true},
	{Name: "sso/connections"},

	{Name: "me"},
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
		if strings.HasPrefix(r.URL.Path, prefix+"/scim/") {
			http.StripPrefix(prefix+"/scim", h.api.SCIMHandler()).ServeHTTP(w, r)
			return
		}
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
		case "organizations":
			h.handleOrganizations(w, r)
		case "organization-members":
			h.handleOrganizationMembers(w, r)
		case "organization-members/add":
			h.handleOrganizationMemberMutation(w, r, "add")
		case "organization-members/remove":
			h.handleOrganizationMemberMutation(w, r, "remove")
		case "organization-members/role":
			h.handleOrganizationMemberMutation(w, r, "role")
		case "clear-active-organization":
			h.handleClearActiveOrganization(w, r)
		case "admin-users":
			h.handleAdminUsers(w, r)
		case "admin-users/role":
			h.handleAdminUserRole(w, r)
		case "admin-users/ban":
			h.handleAdminUserBan(w, r, true)
		case "admin-users/unban":
			h.handleAdminUserBan(w, r, false)
		case "admin-user-sessions":
			h.handleAdminUserSessions(w, r)
		case "admin-user-sessions/revoke":
			h.handleAdminUserSessionRevoke(w, r)
		case "impersonate":
			h.handleImpersonate(w, r)
		case "stop-impersonating":
			h.handleStopImpersonating(w, r)
		case "passkeys/register-begin":
			h.handlePasskeyRegisterBegin(w, r)
		case "passkeys/register-finish":
			h.handlePasskeyRegisterFinish(w, r)
		case "passkeys/signin-begin":
			h.handlePasskeySignInBegin(w, r)
		case "passkeys/signin-finish":
			h.handlePasskeySignInFinish(w, r)
		case "passkeys":
			h.handlePasskeys(w, r)
		case "passkeys/delete":
			h.handlePasskeyDelete(w, r)
		case "oauth/authorize":
			h.handleOAuthAuthorize(w, r)
		case "oauth/token":
			h.handleOAuthToken(w, r)
		case "oauth/device/authorize":
			h.handleDeviceAuthorize(w, r)
		case "oauth/device/token":
			h.handleDeviceToken(w, r)
		case "oauth/device/approve":
			h.handleDeviceApprove(w, r)
		case "saml/start":
			h.handleSAMLStart(w, r)
		case "saml/acs":
			h.handleSAMLACS(w, r)
		case "sso/start":
			h.handleSSOStart(w, r)
		case "sso/callback":
			h.handleSSOCallback(w, r)
		case "sso/connections":
			h.handleSSOConnections(w, r)

		case "set-active-organization":
			h.handleSetActiveOrganization(w, r)
		case "active-organization":
			h.handleActiveOrganization(w, r)
		case "me":
			h.handleMe(w, r)
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
	in.UserAgent = clientUserAgent(r)
	result, err := h.api.SignUp(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	body := map[string]any{"user": result.User}
	if result.SessionToken != "" {
		if _, err := h.api.SetSessionCookies(w, result.SessionToken); err != nil {
			writeAuthError(w, err)
			return
		}
		h.api.SetLastMethodCookie(w, "email")
		body["session_token"] = result.SessionToken
	}
	writeJSON(w, http.StatusCreated, body)
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
	in.UserAgent = clientUserAgent(r)
	result, err := h.api.SignIn(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if result.TwoFactorChallenge != "" {
		// A challenge is not a sign-in: no Session exists yet, so no last
		// sign-in method is recorded until the second factor completes.
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
	body := map[string]any{
		"user":          result.User,
		"session_token": result.SessionToken,
		"csrf_token":    csrfToken,
	}
	h.writeSignInMethod(w, body, result.LastSignInMethod)
	writeJSON(w, http.StatusOK, body)
}

// writeSignInMethod records the Sign-in method of a response that established
// a Session: it writes the signed cookie when the feature is enabled and adds
// last_sign_in_method to the response body, so a flow cannot report one
// without the other. body may be nil for responses without a JSON body.
func (h *Handler) writeSignInMethod(w http.ResponseWriter, body map[string]any, method string) {
	h.api.SetLastMethodCookie(w, method)
	if body != nil {
		body["last_sign_in_method"] = method
	}
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
		UserAgent:    clientUserAgent(r),
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
	in.UserAgent = clientUserAgent(r)
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
	body := map[string]any{"user": result.User, "session_token": result.SessionToken}
	h.writeSignInMethod(w, body, result.LastSignInMethod)
	writeJSON(w, http.StatusOK, body)
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

func (h *Handler) adminIdentity(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return "", "", false
	}
	return h.api.AdminActor(r, user.ID), h.api.SessionTokenFromRequest(r), true
}

func (h *Handler) handleOrganizations(w http.ResponseWriter, r *http.Request) {
	actor, sessionToken, ok := h.adminIdentity(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		result, err := h.api.ListOrganizations(r.Context(), core.ListOrganizationsInput{UserID: actor, SessionToken: sessionToken})
		if err != nil {
			writeAuthError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case http.MethodPost:
		var in core.CreateOrganizationInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
			return
		}
		in.OwnerID, in.SessionToken = actor, sessionToken
		result, err := h.api.CreateOrganization(r.Context(), in)
		if err != nil {
			writeAuthError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleOrganizationMembers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	actor, sessionToken, ok := h.adminIdentity(w, r)
	if !ok {
		return
	}
	orgID := r.URL.Query().Get("organization_id")
	result, err := h.api.ListOrganizationMembers(r.Context(), orgID, actor, sessionToken)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type organizationMemberInput struct {
	OrgID  string `json:"organization_id"`
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func (h *Handler) handleOrganizationMemberMutation(w http.ResponseWriter, r *http.Request, action string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	actor, sessionToken, ok := h.adminIdentity(w, r)
	if !ok {
		return
	}
	var in organizationMemberInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	var err error
	switch action {
	case "add":
		err = h.api.AddOrganizationMember(r.Context(), core.AddOrganizationMemberInput{
			OrgID: in.OrgID, UserID: in.UserID, Role: in.Role, ActorID: actor, SessionToken: sessionToken,
		})
	case "remove":
		err = h.api.RemoveOrganizationMember(r.Context(), in.OrgID, in.UserID, actor, sessionToken)
	case "role":
		err = h.api.SetOrganizationMemberRole(r.Context(), in.OrgID, in.UserID, in.Role, actor, sessionToken)
	}
	if err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleClearActiveOrganization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := h.api.Authenticate(w, r, true); !ok {
		return
	}
	h.api.ClearActiveOrganizationCookie(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	actor, sessionToken, ok := h.adminIdentity(w, r)
	if !ok {
		return
	}
	result, err := h.api.AdminListUsers(r.Context(), core.AdminListUsersInput{ActorID: actor, SessionToken: sessionToken})
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type adminRoleInput struct {
	UserID string   `json:"user_id"`
	Roles  []string `json:"roles"`
}

func (h *Handler) handleAdminUserRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	actor, sessionToken, ok := h.adminIdentity(w, r)
	if !ok {
		return
	}
	var in adminRoleInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	if err := h.api.AdminSetUserRole(r.Context(), core.AdminSetUserRoleInput{
		ActorID: actor, SessionToken: sessionToken, UserID: in.UserID, Roles: in.Roles,
	}); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type adminUserInput struct {
	UserID string `json:"user_id"`
	Reason string `json:"reason"`
}

func (h *Handler) handleAdminUserBan(w http.ResponseWriter, r *http.Request, ban bool) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	actor, sessionToken, ok := h.adminIdentity(w, r)
	if !ok {
		return
	}
	var in adminUserInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	if ban {
		err := h.api.BanUser(r.Context(), core.BanUserInput{
			ActorID: actor, SessionToken: sessionToken, UserID: in.UserID, Reason: in.Reason,
		})
		if err != nil {
			writeAuthError(w, err)
			return
		}
	} else {
		err := h.api.UnbanUser(r.Context(), core.UnbanUserInput{
			ActorID: actor, SessionToken: sessionToken, UserID: in.UserID,
		})
		if err != nil {
			writeAuthError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleAdminUserSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	actor, sessionToken, ok := h.adminIdentity(w, r)
	if !ok {
		return
	}
	result, err := h.api.AdminListUserSessions(r.Context(), actor, r.URL.Query().Get("user_id"), sessionToken)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleAdminUserSessionRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	actor, sessionToken, ok := h.adminIdentity(w, r)
	if !ok {
		return
	}
	var in struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	if err := h.api.AdminRevokeUserSession(r.Context(), actor, in.SessionID, sessionToken); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type impersonateInput struct {
	UserID string `json:"user_id"`
}

func (h *Handler) handleImpersonate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	actor, sessionToken, ok := h.adminIdentity(w, r)
	if !ok {
		return
	}
	var in impersonateInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	result, err := h.api.ImpersonateUser(r.Context(), core.ImpersonateUserInput{
		ActorID: actor, SessionToken: sessionToken, UserID: in.UserID,
	})
	if err != nil {
		writeAuthError(w, err)
		return
	}
	h.api.SetImpersonationCookie(w, actor, sessionToken)
	if _, err := h.api.SetSessionCookies(w, result.Token); err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleStopImpersonating(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.StopImpersonatingInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.AdminID, in.OriginalToken = h.api.ImpersonationFromRequest(r)
	original, err := h.api.StopImpersonating(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	h.api.ClearImpersonationCookie(w)
	if original != "" {
		if _, err := h.api.SetSessionCookies(w, original); err != nil {
			writeAuthError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	result, err := h.api.BeginPasskeyRegistration(r.Context(), core.PasskeyRegistrationInput{
		UserID: user.ID, SessionToken: h.api.SessionTokenFromRequest(r),
	})
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	var in core.PasskeyFinishInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.SessionToken = h.api.SessionTokenFromRequest(r)
	if err := h.api.FinishPasskeyRegistration(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	_ = user
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handlePasskeySignInBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	result, err := h.api.BeginPasskeySignIn(r.Context())
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handlePasskeySignInFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.PasskeyFinishSignInInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	result, err := h.api.FinishPasskeySignIn(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if _, err := h.api.SetSessionCookies(w, result.SessionToken); err != nil {
		writeAuthError(w, err)
		return
	}
	h.api.SetLastMethodCookie(w, result.LastSignInMethod)
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handlePasskeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	result, err := h.api.ListPasskeys(r.Context(), core.PasskeyListInput{
		UserID: user.ID, SessionToken: h.api.SessionTokenFromRequest(r),
	})
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	var in core.PasskeyDeleteInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.UserID = user.ID
	in.SessionToken = h.api.SessionTokenFromRequest(r)
	if err := h.api.DeletePasskey(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// decodeOAuthRequest accepts form-encoded and JSON bodies.
func decodeOAuthRequest(r *http.Request, out any) error {
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return json.NewDecoder(r.Body).Decode(out)
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	values := r.PostForm
	set := func(name, value string) {
		if values.Get(name) == "" {
			values.Set(name, value)
		}
	}
	set("client_id", r.URL.Query().Get("client_id"))
	set("redirect_uri", r.URL.Query().Get("redirect_uri"))
	set("response_type", r.URL.Query().Get("response_type"))
	set("scope", r.URL.Query().Get("scope"))
	set("state", r.URL.Query().Get("state"))
	set("code_challenge", r.URL.Query().Get("code_challenge"))
	set("audience", r.URL.Query().Get("audience"))
	return decodeForm(values, out)
}

// decodeForm maps form values onto a struct's json-tagged string fields.
func decodeForm(values url.Values, out any) error {
	fields := make(map[string]string, len(values))
	for key := range values {
		fields[key] = values.Get(key)
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func writeOAuthError(w http.ResponseWriter, code string, description string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{
		"error": code, "error_description": description,
	})
}

func (h *Handler) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	var in core.OAuthAuthorizeInput
	if err := decodeOAuthRequest(r, &in); err != nil {
		writeOAuthError(w, "invalid_request", "invalid request")
		return
	}
	in.UserID = user.ID
	result, err := h.api.OAuthAuthorize(r.Context(), in)
	if err != nil {
		writeOAuthError(w, "access_denied", "authorization denied")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.OAuthTokenInput
	if err := decodeOAuthRequest(r, &in); err != nil {
		writeOAuthError(w, "invalid_request", "invalid request")
		return
	}
	var result *core.OAuthTokenResult
	var err error
	switch in.GrantType {
	case "authorization_code":
		result, err = h.api.OAuthExchange(r.Context(), in)
	case "refresh_token":
		result, err = h.api.OAuthRefresh(r.Context(), in)
	default:
		writeOAuthError(w, "unsupported_grant_type", "unsupported grant type")
		return
	}
	if err != nil {
		writeOAuthError(w, "invalid_grant", "grant rejected")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.DeviceAuthorizeInput
	if err := decodeOAuthRequest(r, &in); err != nil {
		writeOAuthError(w, "invalid_request", "invalid request")
		return
	}
	result, err := h.api.BeginDeviceAuthorization(r.Context(), in)
	if err != nil {
		writeOAuthError(w, "invalid_request", "device authorization rejected")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		GrantType  string `json:"grant_type"`
		DeviceCode string `json:"device_code"`
	}
	if err := decodeOAuthRequest(r, &in); err != nil {
		writeOAuthError(w, "invalid_request", "invalid request")
		return
	}
	result, err := h.api.ExchangeDeviceAuthorization(r.Context(), in.DeviceCode)
	if err != nil {
		if errors.Is(err, core.ErrOAuthSlowDown) {
			writeOAuthError(w, "slow_down", "polling too quickly")
			return
		}
		writeOAuthError(w, "authorization_pending", "authorization pending")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	var in core.DeviceApproveInput
	if err := decodeOAuthRequest(r, &in); err != nil {
		writeOAuthError(w, "invalid_request", "invalid request")
		return
	}
	in.UserID = user.ID
	if err := h.api.ApproveDeviceAuthorization(r.Context(), in); err != nil {
		writeOAuthError(w, "invalid_grant", "device code rejected")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleSAMLStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.SAMLStartInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	result, err := h.api.StartSAMLSignIn(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	for _, cookie := range result.Cookies {
		http.SetCookie(w, cookie)
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	result, err := h.api.CompleteSAMLSignIn(r.Context(), r.FormValue("state"), r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if _, err := h.api.SetSessionCookies(w, result.SessionToken); err != nil {
		writeAuthError(w, err)
		return
	}
	h.api.SetActiveOrganizationCookie(w, result.OrganizationID)
	h.api.SetLastMethodCookie(w, "saml")
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in core.SSOStartInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	result, err := h.api.StartSSOSignIn(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	result, err := h.api.CompleteSSOSignIn(r.Context(), core.SSOCallbackInput{
		State: r.URL.Query().Get("state"), Code: r.URL.Query().Get("code"),
	})
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if _, err := h.api.SetSessionCookies(w, result.SessionToken); err != nil {
		writeAuthError(w, err)
		return
	}
	h.api.SetActiveOrganizationCookie(w, result.OrganizationID)
	h.api.SetLastMethodCookie(w, "sso")
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleSSOConnections(w http.ResponseWriter, r *http.Request) {
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		result, err := h.api.ListSSOConnections(r.Context(), h.api.SessionTokenFromRequest(r))
		if err != nil {
			writeAuthError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case http.MethodDelete:
		h.handleSSODelete(w, r)
	case http.MethodPost:
		var in core.CreateSSOConnectionInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
			return
		}
		in.SessionToken = h.api.SessionTokenFromRequest(r)
		result, err := h.api.CreateSSOConnection(r.Context(), in)
		if err != nil {
			writeAuthError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
	_ = user
}

func (h *Handler) handleSSODelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := h.api.Authenticate(w, r, true); !ok {
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	if err := h.api.DeleteSSOConnection(r.Context(), in.ID, h.api.SessionTokenFromRequest(r)); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleSetActiveOrganization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	var in core.SetActiveOrganizationInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid request")
		return
	}
	in.UserID = user.ID
	in.SessionToken = h.api.SessionTokenFromRequest(r)
	if err := h.api.SetActiveOrganization(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	h.api.SetActiveOrganizationCookie(w, in.OrgID)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleActiveOrganization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, h.api.ActiveOrganizationFromRequest(r))
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.api.Authenticate(w, r, true)
	if !ok {
		return
	}
	accounts, err := h.api.ListAccounts(r.Context(), core.ListAccountsInput{UserID: user.ID})
	if err != nil {
		writeAuthError(w, err)
		return
	}
	username := ""
	for _, account := range accounts.Accounts {
		if account.Provider == core.UsernameProvider {
			username = account.ProviderUserID
			break
		}
	}
	writeJSON(w, http.StatusOK, &core.SessionUser{
		ID: user.ID, Email: user.Email, EmailVerified: user.EmailVerified, Name: user.Name,
		Disabled: user.Disabled, Username: username, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
	})
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
	in.UserAgent = clientUserAgent(r)
	result, err := h.api.VerifyEmailAndSignIn(r.Context(), in)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	body := map[string]any{"user": result.User}
	if result.SessionToken != "" {
		if _, err := h.api.SetSessionCookies(w, result.SessionToken); err != nil {
			writeAuthError(w, err)
			return
		}
		h.api.SetLastMethodCookie(w, "email")
		body["session_token"] = result.SessionToken
	}
	writeJSON(w, http.StatusOK, body)
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
	in := core.RequestDeleteUserInput{
		UserID:       user.ID,
		SessionToken: h.api.SessionTokenFromRequest(r),
		RateLimitKey: h.clientIP(r),
	}
	if err := h.api.RequestUserDeletion(r.Context(), in); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleConfirmAccountDeletion(w http.ResponseWriter, r *http.Request) {
	if h.api.IsImpersonating(r) {
		writeError(w, http.StatusForbidden, "forbidden", "account deletion is disabled while impersonating")
		return
	}
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

// clientUserAgent returns the raw User-Agent header of the request, empty when
// the client sent none.
func clientUserAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}
