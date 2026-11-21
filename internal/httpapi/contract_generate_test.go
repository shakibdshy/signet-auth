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
	if len(doc.Paths) != len(ContractFor().Endpoints) {
		t.Errorf("paths = %d, want %d", len(doc.Paths), len(ContractFor().Endpoints))
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

func TestGenerateDocumentsAuthenticationRequirements(t *testing.T) {
	data, err := Generate(ContractFor())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var doc struct {
		Paths map[string]struct {
			Post struct {
				Security   []map[string][]string `json:"security"`
				Parameters []struct {
					Name string `json:"name"`
					In   string `json:"in"`
				} `json:"parameters"`
			} `json:"post"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Enum []string `json:"enum"`
				} `json:"properties"`
			} `json:"schemas"`
			SecuritySchemes map[string]json.RawMessage `json:"securitySchemes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	codes := doc.Components.Schemas["ApiError"].Properties["error"].Enum
	found := false
	for _, code := range codes {
		if code == "unauthorized" {
			found = true
		}
	}
	if !found {
		t.Error("ApiError enum missing unauthorized code")
	}
	if len(doc.Components.SecuritySchemes) == 0 {
		t.Error("no security schemes published")
	}
	op := doc.Paths["/change-password"].Post
	if len(op.Security) == 0 {
		t.Error("change-password has no security requirement")
	}
	csrf := false
	for _, p := range op.Parameters {
		if p.Name == "X-CSRF-Token" && p.In == "header" {
			csrf = true
		}
	}
	if !csrf {
		t.Error("change-password does not document the CSRF header")
	}
}
