// Package openapi exposes the generated Signet OpenAPI document to applications.
package openapi

import _ "embed"

//go:embed signet.openapi.json
var spec []byte

// Spec returns the generated OpenAPI 3.1 document. The returned slice is shared
// and must not be modified by callers.
func Spec() []byte { return spec }
