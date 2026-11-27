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

func TestGenerateReturnsErrorForUnknownResponseRef(t *testing.T) {
	contract := ContractFor()
	contract.Endpoints[0].Methods[0].Response = ResponseSpec{Ref: "NoSuchType"}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Generate panicked: %v", r)
		}
	}()
	if _, err := Generate(contract); err == nil {
		t.Fatal("Generate returned nil error for unknown response ref")
	}
}

func TestGenerateSignUpResponseUsesLowercaseUserKey(t *testing.T) {
	data, err := Generate(ContractFor())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var doc generatedDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	schema, ok := doc.Components.Schemas["SignUpResult"]
	if !ok {
		t.Fatal("missing SignUpResult schema")
	}
	if _, ok := schema.Properties["user"]; !ok {
		t.Fatalf("SignUpResult must declare the user key lowercase; properties: %v", keysOf(schema.Properties))
	}
	if _, ok := schema.Properties["User"]; ok {
		t.Fatal("SignUpResult still declares the Go-cased User key")
	}
}

func keysOf(properties map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(properties))
	for key := range properties {
		keys = append(keys, key)
	}
	return keys
}

func TestGenerateSignInInputEmailOptional(t *testing.T) {
	data, err := Generate(ContractFor())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var doc generatedDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	schema, ok := doc.Components.Schemas["SignInInput"]
	if !ok {
		t.Fatal("missing SignInInput schema")
	}
	if _, ok := schema.Properties["email"]; !ok {
		t.Fatal("SignInInput missing email property")
	}
	for _, name := range schema.Required {
		if name == "email" {
			t.Fatal("SignInInput.email must be optional: username-only sign-in sends an empty email")
		}
	}
	if !contains(schema.Required, "password") {
		t.Fatalf("SignInInput.password must stay required, required = %v", schema.Required)
	}
}

func TestGenerateAddOrganizationMemberInputIdentifiersOptional(t *testing.T) {
	data, err := Generate(ContractFor())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var doc generatedDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	schema, ok := doc.Components.Schemas["AddOrganizationMemberInput"]
	if !ok {
		t.Fatal("missing AddOrganizationMemberInput schema")
	}
	if _, ok := schema.Properties["email"]; !ok {
		t.Fatal("AddOrganizationMemberInput missing email property")
	}
	for _, name := range schema.Required {
		if name == "email" || name == "user_id" {
			t.Fatalf("Membership identifiers must be optional so callers can send either one, required = %v", schema.Required)
		}
	}
	if !contains(schema.Required, "org_id") || !contains(schema.Required, "role") {
		t.Fatalf("org_id and role must stay required, required = %v", schema.Required)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
