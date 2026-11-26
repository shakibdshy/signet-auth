package httpapi

import (
	"net/http"
	"reflect"

	"github.com/shakibdshy/signet-auth/internal/core"
)

// Schema describes a JSON value: either a Go type to reflect over, or a named
// reference into the generated components section.
type Schema struct {
	Type reflect.Type
	Ref  string
}

// Field is a named property of a wrapped JSON response object.
type Field struct {
	Name   string
	Schema Schema
}

// ResponseSpec describes a response body. A Ref means a single typed body,
// Fields means a wrapper object, and neither means no body.
type ResponseSpec struct {
	Ref      string
	Fields   []Field
	Optional []string
}

// Parameter is an HTTP input that is not part of the JSON request body.
type Parameter struct {
	Name     string
	In       string // "query" or "header"
	Required bool
	Type     string // OpenAPI scalar type
}

// Method is one HTTP method served by an endpoint.
type Method struct {
	Verb       string
	Request    reflect.Type
	Response   ResponseSpec
	Status     int
	Parameters []Parameter
}

// ContractEndpoint describes one route and its methods.
type ContractEndpoint struct {
	Name      string
	Methods   []Method
	Auth      bool
	Anonymous bool
}

// ErrorSpec maps a sentinel to the wire error code and status. A nil Sentinel
// denotes a code-only entry used by the API description.
type ErrorSpec struct {
	Sentinel error
	Status   int
	Code     string
	Message  string
}

// Contract is the complete description of Signet's HTTP surface.
type Contract struct {
	Endpoints []ContractEndpoint
	Errors    []ErrorSpec
	// OptionalFields overrides tag-derived requiredness for inputs whose Go
	// struct uses a single shape for mutually exclusive runtime variants.
	OptionalFields map[string][]string
}

func typ(t reflect.Type) Schema { return Schema{Type: t} }

func ref(name string) Schema { return Schema{Ref: name} }

func strField(name string) Field { return Field{Name: name, Schema: typ(reflect.TypeOf(""))} }

func typeField(name string, value any) Field {
	return Field{Name: name, Schema: typ(reflect.TypeOf(value))}
}

// ContractFor returns the declared contract for Signet's HTTP endpoints.
// Order matters: error sentinels are matched first-match-wins.
func ContractFor() Contract {
	user := typeField("user", core.User{})
	return Contract{
		Endpoints: []ContractEndpoint{
			{Name: "signup", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.SignUpInput{}),
				Response: ResponseSpec{Ref: "SignUpResult"}, Status: http.StatusCreated,
			}}},
			{Name: "signin", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.SignInInput{}),
				Response: ResponseSpec{
					Fields: []Field{
						user, strField("session_token"), strField("csrf_token"),
						strField("two_factor_challenge"), strField("error"),
						strField("last_sign_in_method"),
					},
					Optional: []string{"session_token", "csrf_token", "two_factor_challenge", "error", "last_sign_in_method"},
				}, Status: http.StatusOK,
			}}},
			{Name: "last-sign-in-method", Anonymous: true, Methods: []Method{{
				Verb: "GET", Response: ResponseSpec{Fields: []Field{strField("method")}}, Status: http.StatusOK,
			}}},
			{Name: "organizations", Methods: []Method{{
				Verb: "GET", Response: ResponseSpec{Ref: "ListOrganizationsResult"}, Status: http.StatusOK,
			}, {
				Verb: "POST", Request: reflect.TypeOf(core.CreateOrganizationInput{}),
				Response: ResponseSpec{Ref: "CreateOrganizationResult"}, Status: http.StatusCreated,
			}}},
			{Name: "organization-members", Methods: []Method{{
				Verb: "GET",
				Parameters: []Parameter{
					{Name: "organization_id", In: "query", Required: true, Type: "string"},
				},
				Response: ResponseSpec{Ref: "ListOrganizationMembersResult"}, Status: http.StatusOK,
			}}},
			{Name: "organization-members/add", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.AddOrganizationMemberInput{}), Status: http.StatusOK,
			}}},
			{Name: "organization-members/remove", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.AddOrganizationMemberInput{}), Status: http.StatusOK,
			}}},
			{Name: "organization-members/role", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.AddOrganizationMemberInput{}), Status: http.StatusOK,
			}}},
			{Name: "clear-active-organization", Methods: []Method{{
				Verb: "POST", Status: http.StatusOK,
			}}},
			{Name: "admin-users", Methods: []Method{{
				Verb: "GET", Response: ResponseSpec{Ref: "AdminListUsersResult"}, Status: http.StatusOK,
			}}},
			{Name: "admin-users/role", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.AdminSetUserRoleInput{}), Status: http.StatusOK,
			}}},
			{Name: "admin-users/ban", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.BanUserInput{}), Status: http.StatusOK,
			}}},
			{Name: "admin-users/unban", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.UnbanUserInput{}), Status: http.StatusOK,
			}}},
			{Name: "admin-user-sessions", Methods: []Method{{
				Verb: "GET",
				Parameters: []Parameter{
					{Name: "user_id", In: "query", Required: true, Type: "string"},
				},
				Response: ResponseSpec{Ref: "ListSessionsResult"}, Status: http.StatusOK,
			}}},
			{Name: "admin-user-sessions/revoke", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.RevokeSessionInput{}), Status: http.StatusOK,
			}}},
			{Name: "impersonate", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.ImpersonateUserInput{}),
				Response: ResponseSpec{Ref: "ImpersonationResult"}, Status: http.StatusOK,
			}}},
			{Name: "stop-impersonating", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.StopImpersonatingInput{}), Status: http.StatusOK,
			}}},
			{Name: "passkeys/register-begin", Methods: []Method{{
				Verb: "POST", Response: ResponseSpec{Ref: "PasskeyCeremonyResult"}, Status: http.StatusOK,
			}}},
			{Name: "passkeys/register-finish", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.PasskeyFinishInput{}), Status: http.StatusOK,
			}}},
			{Name: "passkeys/signin-begin", Anonymous: true, Methods: []Method{{
				Verb: "POST", Response: ResponseSpec{Ref: "PasskeyCeremonyResult"}, Status: http.StatusOK,
			}}},
			{Name: "passkeys/signin-finish", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.PasskeyFinishSignInInput{}),
				Response: ResponseSpec{Ref: "SignInResult"}, Status: http.StatusOK,
			}}},
			{Name: "passkeys", Methods: []Method{{
				Verb: "GET", Response: ResponseSpec{Ref: "PasskeyListResult"}, Status: http.StatusOK,
			}}},
			{Name: "passkeys/delete", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.PasskeyDeleteInput{}), Status: http.StatusOK,
			}}},
			{Name: "oauth/authorize", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.OAuthAuthorizeInput{}),
				Response: ResponseSpec{Ref: "OAuthAuthorizeResult"}, Status: http.StatusOK,
			}}},
			{Name: "oauth/token", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.OAuthTokenInput{}),
				Response: ResponseSpec{Ref: "OAuthTokenResult"}, Status: http.StatusOK,
			}}},
			{Name: "oauth/device/authorize", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.DeviceAuthorizeInput{}),
				Response: ResponseSpec{Ref: "DeviceAuthorizeResult"}, Status: http.StatusOK,
			}}},
			{Name: "oauth/device/token", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.OAuthTokenInput{}),
				Response: ResponseSpec{Ref: "OAuthTokenResult"}, Status: http.StatusOK,
			}}},
			{Name: "oauth/device/approve", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.DeviceApproveInput{}), Status: http.StatusOK,
			}}},
			{Name: "saml/start", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.SAMLStartInput{}),
				Response: ResponseSpec{Ref: "SAMLStartResult"}, Status: http.StatusOK,
			}}},
			{Name: "saml/acs", Anonymous: true, Methods: []Method{{
				Verb: "POST", Response: ResponseSpec{Ref: "SAMLACSResult"}, Status: http.StatusOK,
			}}},
			{Name: "sso/start", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.SSOStartInput{}),
				Response: ResponseSpec{Ref: "SSOStartResult"}, Status: http.StatusOK,
			}}},
			{Name: "sso/callback", Anonymous: true, Methods: []Method{{
				Verb: "GET",
				Parameters: []Parameter{
					{Name: "state", In: "query", Required: true, Type: "string"},
					{Name: "code", In: "query", Required: true, Type: "string"},
				},
				Response: ResponseSpec{Ref: "SSOCallbackResult"}, Status: http.StatusOK,
			}}},
			{Name: "sso/connections", Methods: []Method{{
				Verb: "GET", Response: ResponseSpec{Fields: []Field{typeField("connections", []core.SSOConnectionInfo{})}}, Status: http.StatusOK,
			}, {
				Verb: "POST", Request: reflect.TypeOf(core.CreateSSOConnectionInput{}),
				Response: ResponseSpec{Ref: "SSOConnectionInfo"}, Status: http.StatusCreated,
			}, {
				Verb: "DELETE", Request: reflect.TypeOf(core.DeleteSSOConnectionInput{}), Status: http.StatusOK,
			}}},
			{Name: "set-active-organization", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.SetActiveOrganizationInput{}), Status: http.StatusOK,
			}}},
			{Name: "active-organization", Anonymous: true, Methods: []Method{{
				Verb: "GET", Response: ResponseSpec{Fields: []Field{strField("id")}}, Status: http.StatusOK,
			}}},
			{Name: "me", Methods: []Method{{
				Verb: "GET", Response: ResponseSpec{Ref: "SessionUser"}, Status: http.StatusOK,
			}}},
			{Name: "accounts", Methods: []Method{{
				Verb: "GET", Response: ResponseSpec{Fields: []Field{
					typeField("accounts", []core.AccountInfo{}),
				}}, Status: http.StatusOK,
			}}},
			{Name: "unlink-account", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.UnlinkAccountInput{}), Status: http.StatusOK,
			}}},
			{Name: "enable-two-factor", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.EnableTwoFactorInput{}),
				Response: ResponseSpec{Fields: []Field{
					strField("totp_uri"), strField("challenge"), typeField("backup_codes", []string{}),
				}}, Status: http.StatusOK,
			}}},
			{Name: "verify-two-factor", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.VerifyTwoFactorInput{}),
				Response: ResponseSpec{Fields: []Field{
					user, strField("session_token"), strField("last_sign_in_method"),
				}}, Status: http.StatusOK,
			}}},
			{Name: "disable-two-factor", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.DisableTwoFactorInput{}), Status: http.StatusOK,
			}}},
			{Name: "regenerate-backup-codes", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.RegenerateBackupCodesInput{}),
				Response: ResponseSpec{Fields: []Field{
					typeField("backup_codes", []string{}),
				}}, Status: http.StatusOK,
			}}},
			{Name: "send-magic-link", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.SendMagicLinkInput{}), Status: http.StatusOK,
			}}},
			{Name: "verify-magic-link", Anonymous: true, Methods: []Method{{
				Verb: "GET", Response: ResponseSpec{Fields: []Field{
					user, strField("session_token"),
				}}, Status: http.StatusOK,
				Parameters: []Parameter{
					{Name: "token", In: "query", Required: true, Type: "string"},
					{Name: "callback_url", In: "query", Required: false, Type: "string"},
				},
			}}},
			{Name: "send-otp", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.SendEmailOTPInput{}), Status: http.StatusOK,
			}}},
			{Name: "verify-otp", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.VerifyEmailOTPInput{}),
				Response: ResponseSpec{Fields: []Field{
					user, strField("session_token"), strField("last_sign_in_method"),
				}}, Status: http.StatusOK,
			}}},
			{Name: "signout", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.SignOutInput{}), Status: http.StatusNoContent,
			}}},
			{Name: "sessions", Auth: true, Methods: []Method{
				{
					Verb: "GET",
					Response: ResponseSpec{Fields: []Field{
						typeField("sessions", []core.SessionInfo{}),
					}}, Status: http.StatusOK,
				},
				{Verb: "DELETE", Status: http.StatusNoContent},
			}},
			{Name: "session", Auth: true, Methods: []Method{{
				Verb: "DELETE", Status: http.StatusNoContent,
			}}},
			{Name: "token", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.TokenInput{}),
				Response: ResponseSpec{Ref: "TokenPair"}, Status: http.StatusOK,
			}}},
			{Name: "send-verification", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.SendVerificationInput{}), Status: http.StatusOK,
			}}},
			{Name: "verify-email", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.VerifyEmailInput{}),
				Response: ResponseSpec{Ref: "VerifyEmailAndSignInResult"}, Status: http.StatusOK,
			}}},
			{Name: "send-password-reset", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.SendPasswordResetInput{}), Status: http.StatusOK,
			}}},
			{Name: "reset-password", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.ResetPasswordInput{}), Status: http.StatusOK,
			}}},
			{Name: "request-account-deletion", Auth: true, Methods: []Method{{
				Verb: "POST", Status: http.StatusOK,
			}}},
			{Name: "confirm-account-deletion", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.ConfirmDeleteUserInput{}), Status: http.StatusOK,
			}}},
			{Name: "change-email", Auth: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.ChangeEmailInput{}), Status: http.StatusOK,
			}}},
			{Name: "verify-change-email", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.VerifyEmailChangeInput{}), Status: http.StatusOK,
			}}},
			{Name: "change-password", Auth: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.ChangePasswordInput{}), Status: http.StatusOK,
			}}},
			{Name: "oauth/start", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.OAuthStartInput{}),
				Response: ResponseSpec{Ref: "OAuthStartResult"}, Status: http.StatusOK,
			}}},
			{Name: "oauth/callback", Anonymous: true, Methods: []Method{{
				Verb: "GET", Status: http.StatusFound,
				Parameters: []Parameter{
					{Name: "code", In: "query", Required: true, Type: "string"},
					{Name: "state", In: "query", Required: true, Type: "string"},
				},
			}}},
			{Name: "csrf-token", Anonymous: true, Methods: []Method{{
				Verb: "GET", Response: ResponseSpec{Fields: []Field{strField("token")}}, Status: http.StatusOK,
			}}},
			{Name: "api-keys", Methods: []Method{{
				Verb: "GET", Response: ResponseSpec{Ref: "ListAPIKeysResult"}, Status: http.StatusOK,
			}, {
				Verb: "POST", Request: reflect.TypeOf(core.CreateAPIKeyInput{}),
				Response: ResponseSpec{Ref: "CreateAPIKeyResult"}, Status: http.StatusCreated,
			}}},
			{Name: "verify-api-key", Anonymous: true, Methods: []Method{{
				Verb: "POST",
				Parameters: []Parameter{
					{Name: "X-API-Key", In: "header", Required: true, Type: "string"},
				},
				Response: ResponseSpec{Ref: "Principal"}, Status: http.StatusOK,
			}}},
			{Name: "revoke-api-key", Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.RevokeAPIKeyInput{}), Status: http.StatusOK,
			}}},
		},
		OptionalFields: map[string][]string{
			"TokenInput":                 {"email", "password", "refresh_token", "challenge", "code"},
			"SignUpInput":                {"username"},
			"SignInInput":                {"email", "username"},
			"SignUpResult":               {"session_token"},
			"VerifyEmailAndSignInResult": {"session_token"},
			"SignOutInput":               {"session_token"},
			"SendMagicLinkInput":         {"name", "callback_url"},
			"SendEmailOTPInput":          {"name"},
		},
		Errors: []ErrorSpec{
			{core.ErrRateLimited, http.StatusTooManyRequests, "rate_limited", "too many requests"},
			{core.ErrOTPAlreadyUsed, http.StatusUnauthorized, "code_already_used", "this code has already been used; request a new one"},
			{core.ErrInvalidOTP, http.StatusUnauthorized, "invalid_code", "invalid or expired code"},
			{core.ErrMagicLinkAlreadyUsed, http.StatusUnauthorized, "link_already_used", "this magic link has already been used; request a new one"},
			{core.ErrInvalidMagicLink, http.StatusUnauthorized, "invalid_link", "invalid or expired magic link"},
			{core.ErrForbidden, http.StatusForbidden, "forbidden", "permission denied"},
			{core.ErrSSOConnectionNotFound, http.StatusNotFound, "sso_connection_not_found", "sso connection not found"},
			{core.ErrSSODomainNotVerified, http.StatusForbidden, "sso_domain_not_verified", "sso domain not verified"},
			{core.ErrSSOInvalidAssertion, http.StatusUnauthorized, "sso_invalid_assertion", "sso assertion rejected"},
			{core.ErrSAMLInvalidAssertion, http.StatusUnauthorized, "saml_invalid_assertion", "saml assertion rejected"},
			{core.ErrSAMLConnectionNotFound, http.StatusNotFound, "saml_connection_not_found", "saml connection not found"},
			{core.ErrSAMLReplay, http.StatusUnauthorized, "saml_replay", "saml assertion replayed"},
			{core.ErrPasswordCompromised, http.StatusBadRequest, "password_compromised", "password has been compromised"},
			{core.ErrCaptchaRequired, http.StatusBadRequest, "invalid_input", "captcha token required"},
			{core.ErrCaptchaInvalid, http.StatusBadRequest, "invalid_input", "captcha verification failed"},
			{core.ErrCaptchaUnavailable, http.StatusServiceUnavailable, "captcha_unavailable", "captcha provider unavailable"},
			{core.ErrInvalidUsername, http.StatusBadRequest, "invalid_input", "invalid username"},
			{core.ErrUsernameTaken, http.StatusBadRequest, "username_taken", "username already taken"},
			{core.ErrLastAccount, http.StatusBadRequest, "last_account", "cannot unlink the last account"},
			{core.ErrTOTPNotEnabled, http.StatusBadRequest, "two_factor_not_enabled", "second factor is not enabled"},
			{core.ErrTOTPInvalid, http.StatusUnauthorized, "invalid_code", "invalid second factor code"},
			{core.ErrTwoFactorRequired, http.StatusUnauthorized, "two_factor_required", "second factor required"},
			{core.ErrTOTPNotConfigured, http.StatusNotFound, "not_found", "second factor is not configured"},
			{core.ErrTokenInvalid, http.StatusUnauthorized, "invalid_token", "invalid token"},
			{core.ErrTokenExpired, http.StatusUnauthorized, "invalid_token", "invalid token"},
			{core.ErrRefreshReuse, http.StatusUnauthorized, "invalid_token", "invalid token"},
			{core.ErrEmailNotVerified, http.StatusForbidden, "email_not_verified", "email not verified"},
			{core.ErrInvalidCredentials, http.StatusUnauthorized, "invalid_credentials", "invalid credentials"},
			{core.ErrJWTDisabled, http.StatusNotFound, "not_found", "not found"},
			{core.ErrOAuthDisabled, http.StatusNotFound, "not_found", "not found"},
			{core.ErrOAuthProviderNotFound, http.StatusNotFound, "not_found", "not found"},
			{core.ErrOAuthRedirectNotAllowed, http.StatusBadRequest, "invalid_request", "invalid request"},
			{core.ErrOAuthInvalidState, http.StatusBadRequest, "invalid_request", "invalid request"},
			{core.ErrOAuthEmailNotVerified, http.StatusForbidden, "oauth_email_not_verified", "email not verified by provider"},
			{core.ErrOAuthAccountConflict, http.StatusConflict, "oauth_account_conflict", "provider account belongs to another user"},
			{core.ErrEmailAlreadyExists, http.StatusBadRequest, "email_exists", "email already registered"},
			{core.ErrInvalidEmail, http.StatusBadRequest, "invalid_input", "invalid input"},
			{core.ErrPasswordTooShort, http.StatusBadRequest, "invalid_input", "invalid input"},
			{core.ErrPasswordTooLong, http.StatusBadRequest, "invalid_input", "invalid input"},
			{nil, http.StatusForbidden, "csrf", "cross-origin request rejected"},
			{nil, http.StatusUnauthorized, "unauthorized", "authentication required"},
			{nil, http.StatusBadRequest, "invalid_input", "invalid request"},
			{nil, http.StatusInternalServerError, "internal_error", "internal error"},
		},
	}
}
