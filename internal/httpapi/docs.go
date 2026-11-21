package httpapi

import (
	"net/http"
)

// DocsHandler serves the OpenAPI document and a Scalar viewer. It is deliberately
// separate from the authentication handler so applications choose whether and
// where to expose it.
func DocsHandler(spec []byte) http.Handler {
	viewer := []byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Signet API reference</title>
</head>
<body>
  <div id="app"></div>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference@1"></script>
  <script>
    Scalar.createApiReference('#app', { url: './openapi.json' })
  </script>
</body>
</html>
`)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(spec)
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(viewer)
		default:
			http.NotFound(w, r)
		}
	})
}
