package httpapi

import (
	"net/http"

	"github.com/shakibdshy/signet/internal/token"
)

// JWKSHandler publishes only the public half of asymmetric signing keys. It is
// opt-in and is never mounted by Handler.
func JWKSHandler(keys []any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		document, err := token.JWKS(keys)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(document)
	})
}
