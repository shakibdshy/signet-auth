package httpapi

import (
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/shakibdshy/signet-auth/internal/core"
)

func TestContractCoversEveryRoute(t *testing.T) {
	contract := ContractFor()
	if len(contract.Endpoints) != len(Endpoints) {
		t.Fatalf("contract has %d endpoints, route table has %d", len(contract.Endpoints), len(Endpoints))
	}
	for _, route := range Endpoints {
		found := false
		for _, endpoint := range contract.Endpoints {
			if endpoint.Name == route.Name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("route %q has no contract entry", route.Name)
		}
	}
}

func TestContractErrorMapping(t *testing.T) {
	want := map[error]struct {
		status int
		code   string
	}{
		core.ErrRateLimited:             {429, "rate_limited"},
		core.ErrTokenInvalid:            {401, "invalid_token"},
		core.ErrTokenExpired:            {401, "invalid_token"},
		core.ErrRefreshReuse:            {401, "invalid_token"},
		core.ErrEmailNotVerified:        {403, "email_not_verified"},
		core.ErrInvalidCredentials:      {401, "invalid_credentials"},
		core.ErrJWTDisabled:             {404, "not_found"},
		core.ErrOAuthDisabled:           {404, "not_found"},
		core.ErrOAuthProviderNotFound:   {404, "not_found"},
		core.ErrOAuthRedirectNotAllowed: {400, "invalid_request"},
		core.ErrOAuthInvalidState:       {400, "invalid_request"},
		core.ErrOAuthEmailNotVerified:   {403, "oauth_email_not_verified"},
		core.ErrOAuthAccountConflict:    {409, "oauth_account_conflict"},
		core.ErrEmailAlreadyExists:      {400, "email_exists"},
		core.ErrInvalidEmail:            {400, "invalid_input"},
		core.ErrPasswordTooShort:        {400, "invalid_input"},
		core.ErrPasswordTooLong:         {400, "invalid_input"},
	}
	contract := ContractFor()
	for sentinel, expected := range want {
		found := false
		for _, spec := range contract.Errors {
			if errors.Is(spec.Sentinel, sentinel) {
				found = true
				if spec.Status != expected.status || spec.Code != expected.code {
					t.Errorf("%v mapped to %d/%q, want %d/%q", sentinel, spec.Status, spec.Code, expected.status, expected.code)
				}
				break
			}
		}
		if !found {
			t.Errorf("sentinel %v has no error mapping", sentinel)
		}
	}
}

func TestContractRequestAndResponseShapes(t *testing.T) {
	contract := ContractFor()
	byName := make(map[string]ContractEndpoint, len(contract.Endpoints))
	for _, endpoint := range contract.Endpoints {
		byName[endpoint.Name] = endpoint
	}

	signup := byName["signup"]
	if len(signup.Methods) != 1 || signup.Methods[0].Request != reflect.TypeOf(core.SignUpInput{}) {
		t.Errorf("signup request = %v, want core.SignUpInput", signup.Methods)
	}
	signin := byName["signin"]
	if len(signin.Methods) != 1 {
		t.Fatalf("signin methods = %d, want 1", len(signin.Methods))
	}
	fields := signin.Methods[0].Response.Fields
	wantFields := map[string]bool{"user": false, "session_token": false, "csrf_token": false}
	for _, field := range fields {
		if _, ok := wantFields[field.Name]; ok {
			wantFields[field.Name] = true
		}
	}
	for name, found := range wantFields {
		if !found {
			t.Errorf("signin response missing field %q", name)
		}
	}

	callback := byName["oauth/callback"]
	if len(callback.Methods) != 1 || callback.Methods[0].Verb != "GET" {
		t.Errorf("oauth/callback verb = %v, want GET", callback.Methods)
	}
	token := byName["token"]
	if len(token.Methods) != 1 || token.Methods[0].Verb != "POST" {
		t.Errorf("token verb = %v, want POST", token.Methods)
	}
}

func TestContractDescribesCSRFRejection(t *testing.T) {
	for _, spec := range ContractFor().Errors {
		if spec.Code == "csrf" {
			if spec.Status != http.StatusForbidden {
				t.Errorf("csrf status = %d, want 403", spec.Status)
			}
			return
		}
	}
	t.Fatal("contract omits the csrf error code returned by the CSRF guard")
}
