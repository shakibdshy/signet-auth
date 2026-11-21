package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/openapi"
)

func TestDocsHandlerServesTheGeneratedSpec(t *testing.T) {
	rec := httptest.NewRecorder()
	signet.DocsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", got)
	}
	var doc struct {
		OpenAPI string                     `json:"openapi"`
		Paths   map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("spec is not JSON: %v", err)
	}
	if doc.OpenAPI != "3.1.0" || len(doc.Paths) != 13 {
		t.Errorf("spec = %s with %d paths, want 3.1.0 with 13", doc.OpenAPI, len(doc.Paths))
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("docs handler must not set cookies")
	}
}

func TestDocsHandlerServesViewerAndRejectsOtherRequests(t *testing.T) {
	handler := signet.DocsHandler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Scalar") {
		t.Fatalf("viewer: status = %d, body = %.120q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "/openapi.json") {
		t.Error("viewer page must reference the spec URL")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("viewer must not set cookies")
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/unknown", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown path status = %d, want 404", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/openapi.json", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", rec.Code)
	}
}

func TestEmbeddedSpecMatchesGeneratedArtifact(t *testing.T) {
	if len(openapi.Spec()) == 0 {
		t.Fatal("embedded spec is empty")
	}
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openapi.Spec(), &doc); err != nil {
		t.Fatalf("embedded spec is not JSON: %v", err)
	}
	if len(doc.Paths) != 13 {
		t.Errorf("embedded spec has %d paths, want 13", len(doc.Paths))
	}
}
