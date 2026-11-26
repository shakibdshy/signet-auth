package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shakibdshy/signet-auth/internal/core"
)

var timeType = reflect.TypeOf(time.Time{})

var namedTypes = map[string]reflect.Type{
	"TokenPair":                     reflect.TypeOf(core.TokenPair{}),
	"OAuthStartResult":              reflect.TypeOf(core.OAuthStartResult{}),
	"ListAPIKeysResult":             reflect.TypeOf(core.ListAPIKeysResult{}),
	"CreateAPIKeyResult":            reflect.TypeOf(core.CreateAPIKeyResult{}),
	"Principal":                     reflect.TypeOf(core.Principal{}),
	"ListOrganizationsResult":       reflect.TypeOf(core.ListOrganizationsResult{}),
	"CreateOrganizationResult":      reflect.TypeOf(core.CreateOrganizationResult{}),
	"ListOrganizationMembersResult": reflect.TypeOf(core.ListOrganizationMembersResult{}),
	"AdminListUsersResult":          reflect.TypeOf(core.AdminListUsersResult{}),
	"ListSessionsResult":            reflect.TypeOf(core.ListSessionsResult{}),
	"ImpersonationResult":           reflect.TypeOf(core.ImpersonationResult{}),
	"PasskeyCeremonyResult":         reflect.TypeOf(core.PasskeyCeremonyResult{}),
	"PasskeyListResult":             reflect.TypeOf(core.PasskeyListResult{}),
	"SignInResult":                  reflect.TypeOf(core.SignInResult{}),
	"SignUpResult":                  reflect.TypeOf(core.SignUpResult{}),
	"SessionUser":                   reflect.TypeOf(core.SessionUser{}),
	"UserInfo":                      reflect.TypeOf(core.UserInfo{}),
	"VerifyEmailAndSignInResult":    reflect.TypeOf(core.VerifyEmailAndSignInResult{}),
	"OAuthAuthorizeResult":          reflect.TypeOf(core.OAuthAuthorizeResult{}),
	"OAuthTokenResult":              reflect.TypeOf(core.OAuthTokenResult{}),
	"DeviceAuthorizeResult":         reflect.TypeOf(core.DeviceAuthorizeResult{}),
	"SSOStartResult":                reflect.TypeOf(core.SSOStartResult{}),
	"SSOCallbackResult":             reflect.TypeOf(core.SSOCallbackResult{}),
	"SSOConnectionInfo":             reflect.TypeOf(core.SSOConnectionInfo{}),
	"SAMLStartResult":               reflect.TypeOf(core.SAMLStartResult{}),
	"SAMLACSResult":                 reflect.TypeOf(core.SAMLACSResult{}),
}

type oasDocument struct {
	OpenAPI    string                      `json:"openapi"`
	Info       oasInfo                     `json:"info"`
	Paths      map[string]map[string]oasOp `json:"paths"`
	Components oasComponents               `json:"components"`
}

type oasInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type oasComponents struct {
	Schemas         map[string]any `json:"schemas"`
	SecuritySchemes map[string]any `json:"securitySchemes,omitempty"`
}

type oasOp struct {
	OperationID string                 `json:"operationId"`
	Summary     string                 `json:"summary"`
	Parameters  []oasParameter         `json:"parameters,omitempty"`
	Security    []map[string][]string  `json:"security,omitempty"`
	RequestBody *oasRequestBody        `json:"requestBody,omitempty"`
	Responses   map[string]oasResponse `json:"responses"`
}

type oasParameter struct {
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required"`
	Schema   any    `json:"schema"`
}

type oasRequestBody struct {
	Required bool                `json:"required"`
	Content  map[string]oasMedia `json:"content"`
}

type oasMedia struct {
	Schema any `json:"schema"`
}

type oasResponse struct {
	Description string              `json:"description"`
	Content     map[string]oasMedia `json:"content,omitempty"`
}

type generator struct {
	components     map[string]any
	inProgress     map[string]bool
	optionalFields map[string][]string
}

func (g *generator) objectSchema(t reflect.Type, optional []string) any {
	properties := make(map[string]any)
	required := []string{}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = field.Name
		}
		properties[name] = g.schemaFor(field.Type)
		skip := strings.Contains(tag, "omitempty")
		for _, extra := range optional {
			if extra == name {
				skip = true
				break
			}
		}
		if !skip {
			required = append(required, name)
		}
	}
	schema := map[string]any{"type": "object", "properties": properties}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func (g *generator) schemaFor(t reflect.Type) any {
	if t.Kind() == reflect.Pointer {
		underlying := g.schemaFor(t.Elem())
		if m, ok := underlying.(map[string]any); ok {
			m["nullable"] = true
			return m
		}
		return map[string]any{"allOf": []any{underlying}, "nullable": true}
	}
	if t == timeType {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": g.schemaFor(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": g.schemaFor(t.Elem())}
	case reflect.Struct:
		name := t.Name()
		if name == "" {
			return g.objectSchema(t, nil)
		}
		if _, ok := g.components[name]; !ok && !g.inProgress[name] {
			g.inProgress[name] = true
			g.components[name] = g.objectSchema(t, g.optionalFields[name])
			delete(g.inProgress, name)
		}
		return map[string]any{"$ref": "#/components/schemas/" + name}
	default:
		return map[string]any{"type": "object"}
	}
}

func (g *generator) responseSchema(spec ResponseSpec) (any, error) {
	if spec.Ref != "" {
		t, ok := namedTypes[spec.Ref]
		if !ok {
			return nil, fmt.Errorf("unknown response ref: %s", spec.Ref)
		}
		return g.schemaFor(t), nil
	}
	if len(spec.Fields) == 0 {
		return nil, nil
	}
	properties := make(map[string]any, len(spec.Fields))
	required := make([]string, 0, len(spec.Fields))
	optional := make(map[string]bool, len(spec.Optional))
	for _, name := range spec.Optional {
		optional[name] = true
	}
	for _, field := range spec.Fields {
		if field.Schema.Type != nil {
			properties[field.Name] = g.schemaFor(field.Schema.Type)
		} else if field.Schema.Ref != "" {
			t, ok := namedTypes[field.Schema.Ref]
			if !ok {
				return nil, fmt.Errorf("unknown field ref: %s", field.Schema.Ref)
			}
			properties[field.Name] = g.schemaFor(t)
		}
		if !optional[field.Name] {
			required = append(required, field.Name)
		}
	}
	return map[string]any{"type": "object", "properties": properties, "required": required}, nil
}

// Generate produces an OpenAPI 3.1 document describing the contract.
func Generate(contract Contract) ([]byte, error) {
	g := &generator{
		components: make(map[string]any), inProgress: make(map[string]bool), optionalFields: contract.OptionalFields,
	}

	codes := make(map[string]bool)
	codes["invalid_input"] = true
	codes["internal_error"] = true
	for _, spec := range contract.Errors {
		codes[spec.Code] = true
	}
	codeList := make([]string, 0, len(codes))
	for code := range codes {
		codeList = append(codeList, code)
	}
	sort.Strings(codeList)
	g.components["ApiError"] = map[string]any{
		"type":     "object",
		"required": []string{"error", "message"},
		"properties": map[string]any{
			"error":   map[string]any{"type": "string", "enum": codeList},
			"message": map[string]any{"type": "string"},
		},
	}

	doc := oasDocument{
		OpenAPI: "3.1.0",
		Info:    oasInfo{Title: "Signet HTTP API", Version: "1.0.0-beta"},
		Paths:   make(map[string]map[string]oasOp),
	}

	for _, endpoint := range contract.Endpoints {
		operations := make(map[string]oasOp)
		for _, method := range endpoint.Methods {
			op := oasOp{
				OperationID: endpoint.Name + "_" + strings.ToLower(method.Verb),
				// The HTTP method is already shown as a colour-coded badge in
				// the reference UI. Multi-method routes need a short label so
				// their pages do not share an identical title.
				Summary:   operationSummary(endpoint.Name, method.Verb, len(endpoint.Methods) > 1),
				Responses: make(map[string]oasResponse),
			}
			if method.Request != nil {
				op.RequestBody = &oasRequestBody{
					Required: true,
					Content: map[string]oasMedia{
						"application/json": {Schema: g.schemaFor(method.Request)},
					},
				}
			}
			for _, parameter := range method.Parameters {
				op.Parameters = append(op.Parameters, oasParameter{
					Name: parameter.Name, In: parameter.In, Required: parameter.Required,
					Schema: map[string]any{"type": parameter.Type},
				})
			}
			if endpoint.Auth {
				op.Security = []map[string][]string{{"sessionCookie": {}}}
			}
			if !endpoint.Anonymous && (method.Verb == "POST" || method.Verb == "PUT" || method.Verb == "PATCH" || method.Verb == "DELETE") {
				op.Parameters = append(op.Parameters, oasParameter{
					Name: "X-CSRF-Token", In: "header", Required: false,
					Schema: map[string]any{"type": "string"},
				})
			}
			success := oasResponse{Description: "Success"}
			schema, err := g.responseSchema(method.Response)
			if err != nil {
				return nil, err
			}
			if schema != nil {
				success.Content = map[string]oasMedia{"application/json": {Schema: schema}}
			}
			op.Responses[strconv.Itoa(method.Status)] = success
			// A status can carry several error codes, so describe the status
			// itself rather than picking one code that mislabels other endpoints.
			statuses := make(map[string]bool)
			for _, spec := range contract.Errors {
				statuses[strconv.Itoa(spec.Status)] = true
			}
			for status := range statuses {
				if _, exists := op.Responses[status]; exists {
					continue
				}
				op.Responses[status] = oasResponse{
					Description: statusText(status),
					Content: map[string]oasMedia{
						"application/json": {Schema: map[string]any{"$ref": "#/components/schemas/ApiError"}},
					},
				}
			}
			operations[strings.ToLower(method.Verb)] = op
		}
		doc.Paths["/"+endpoint.Name] = operations
	}
	doc.Components.Schemas = g.components
	doc.Components.SecuritySchemes = map[string]any{
		"sessionCookie": map[string]any{
			"type": "apiKey", "in": "cookie", "name": "signet_session",
		},
		"csrfToken": map[string]any{
			"type": "apiKey", "in": "header", "name": "X-CSRF-Token",
		},
	}

	return json.MarshalIndent(doc, "", "  ")
}

func statusText(status string) string {
	n, err := strconv.Atoi(status)
	if err != nil {
		return status
	}
	return http.StatusText(n)
}

// operationSummary returns the reference title for an operation. Multi-method
// routes get a human-readable suffix; the HTTP verb stays in the method badge.
func operationSummary(name, verb string, shared bool) string {
	if !shared {
		return "/" + name
	}
	labels := map[string]string{
		"api-keys|GET": "list", "api-keys|POST": "create",
		"organizations|GET": "list", "organizations|POST": "create",
		"sessions|GET": "list", "sessions|DELETE": "revoke all",
	}
	if label, ok := labels[name+"|"+verb]; ok {
		return "/" + name + " · " + label
	}
	return "/" + name
}
