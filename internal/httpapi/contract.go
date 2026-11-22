package httpapi

import (
	"net/http"
	"reflect"

	"github.com/shakibdshy/signet/internal/core"
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
	Ref    string
	Fields []Field
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
				Response: ResponseSpec{Fields: []Field{user}}, Status: http.StatusCreated,
			}}},
			{Name: "signin", Anonymous: true, Methods: []Method{{
				Verb: "POST", Request: reflect.TypeOf(core.SignInInput{}),
				Response: ResponseSpec{Fields: []Field{
					user, strField("session_token"), strField("csrf_token"),
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
					user, strField("session_token"),
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
				Verb: "POST", Request: reflect.TypeOf(core.VerifyEmailInput{}), Status: http.StatusOK,
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
		},
		OptionalFields: map[string][]string{
			"TokenInput":         {"email", "password", "refresh_token"},
			"SendMagicLinkInput": {"name", "callback_url"},
			"SendEmailOTPInput":  {"name"},
		},
		Errors: []ErrorSpec{
			{core.ErrRateLimited, http.StatusTooManyRequests, "rate_limited", "too many requests"},
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
