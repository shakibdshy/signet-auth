package httpapi

import (
	"encoding/json"
	"testing"
)

type generatedDoc struct {
	OpenAPI string `json:"openapi"`
	Paths   map[string]struct {
		Post json.RawMessage `json:"post"`
		Get  json.RawMessage `json:"get"`
	} `json:"paths"`
	Components struct {
		Schemas map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Required   []string                   `json:"required"`
		} `json:"schemas"`
	} `json:"components"`
}

func TestGenerateOpenAPIDocument(t *testing.T) {
	data, err := Generate(ContractFor())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var doc generatedDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Errorf("openapi = %q, want 3.1.0", doc.OpenAPI)
	}
	if len(doc.Paths) != 13 {
		t.Errorf("paths = %d, want 13", len(doc.Paths))
	}
	signup, ok := doc.Paths["/signup"]
	if !ok || len(signup.Post) == 0 {
		t.Fatalf("missing POST /signup")
	}
	schema, ok := doc.Components.Schemas["SignUpInput"]
	if !ok {
		t.Fatal("missing SignUpInput schema")
	}
	for _, name := range []string{"email", "password"} {
		if _, ok := schema.Properties[name]; !ok {
			t.Errorf("SignUpInput missing property %q", name)
		}
	}
	if _, ok := schema.Properties["rate_limit_key"]; ok {
		t.Error("SignUpInput must not expose json:\"-\" field rate_limit_key")
	}
}

func TestGenerateTokenInputVariants(t *testing.T) {
	data, err := Generate(ContractFor())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var doc generatedDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	token := doc.Components.Schemas["TokenInput"]
	if len(token.Required) != 0 {
		t.Errorf("TokenInput required = %v, want none (email/password or refresh_token)", token.Required)
	}
}
