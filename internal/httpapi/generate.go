package httpapi

import (
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shakibdshy/signet/internal/core"
)

var timeType = reflect.TypeOf(time.Time{})

var namedTypes = map[string]reflect.Type{
	"TokenPair":        reflect.TypeOf(core.TokenPair{}),
	"OAuthStartResult": reflect.TypeOf(core.OAuthStartResult{}),
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
	Schemas map[string]any `json:"schemas"`
}

type oasOp struct {
	OperationID string                 `json:"operationId"`
	Summary     string                 `json:"summary"`
	Parameters  []oasParameter         `json:"parameters,omitempty"`
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

func (g *generator) responseSchema(spec ResponseSpec) any {
	if spec.Ref != "" {
		t, ok := namedTypes[spec.Ref]
		if !ok {
			panic("unknown response ref: " + spec.Ref)
		}
		return g.schemaFor(t)
	}
	if len(spec.Fields) == 0 {
		return nil
	}
	properties := make(map[string]any, len(spec.Fields))
	required := make([]string, 0, len(spec.Fields))
	for _, field := range spec.Fields {
		if field.Schema.Type != nil {
			properties[field.Name] = g.schemaFor(field.Schema.Type)
		} else if field.Schema.Ref != "" {
			properties[field.Name] = g.schemaFor(namedTypes[field.Schema.Ref])
		}
		required = append(required, field.Name)
	}
	return map[string]any{"type": "object", "properties": properties, "required": required}
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
		Info:    oasInfo{Title: "Signet HTTP API", Version: "0.1.0"},
		Paths:   make(map[string]map[string]oasOp),
	}

	for _, endpoint := range contract.Endpoints {
		operations := make(map[string]oasOp)
		for _, method := range endpoint.Methods {
			op := oasOp{
				OperationID: endpoint.Name + "_" + strings.ToLower(method.Verb),
				Summary:     strings.ToUpper(method.Verb) + " /" + endpoint.Name,
				Responses:   make(map[string]oasResponse),
			}
			if method.Request != nil {
				op.RequestBody = &oasRequestBody{
					Required: true,
					Content: map[string]oasMedia{
						"application/json": {Schema: g.schemaFor(method.Request)},
					},
				}
			}
			if endpoint.Name == "oauth/callback" {
				op.Parameters = []oasParameter{
					{Name: "code", In: "query", Required: true, Schema: map[string]any{"type": "string"}},
					{Name: "state", In: "query", Required: true, Schema: map[string]any{"type": "string"}},
				}
			}
			success := oasResponse{Description: "Success"}
			if schema := g.responseSchema(method.Response); schema != nil {
				success.Content = map[string]oasMedia{"application/json": {Schema: schema}}
			}
			op.Responses[strconv.Itoa(method.Status)] = success
			for _, spec := range contract.Errors {
				status := strconv.Itoa(spec.Status)
				if _, exists := op.Responses[status]; exists {
					continue
				}
				op.Responses[status] = oasResponse{
					Description: spec.Code,
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

	return json.MarshalIndent(doc, "", "  ")
}
