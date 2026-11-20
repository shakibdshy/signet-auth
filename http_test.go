package signet_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shakibdshy/signet"
)

func TestHandlerEndpointsAreWired(t *testing.T) {
	client, err := signet.New(completeConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handler := client.Handler()
	paths := []string{
		"/verify-email",
		"/reset-password",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
			if rec.Code != http.StatusNotImplemented {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusNotImplemented)
			}
		})
	}
}

func TestMiddlewareComposes(t *testing.T) {
	client, err := signet.New(completeConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	middlewares := map[string]func(http.Handler) http.Handler{
		"RequireAuth":  client.RequireAuth,
		"OptionalAuth": client.OptionalAuth,
	}
	for name, middleware := range middlewares {
		t.Run(name, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			})
			rec := httptest.NewRecorder()
			middleware(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if !called {
				t.Error("next handler was not called")
			}
			if rec.Code != http.StatusNoContent {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
			}
		})
	}
}

func TestUserFromContextWithoutUser(t *testing.T) {
	user, ok := signet.UserFromContext(context.Background())
	if ok || user != nil {
		t.Fatalf("UserFromContext() = (%v, %v), want (nil, false)", user, ok)
	}
}
