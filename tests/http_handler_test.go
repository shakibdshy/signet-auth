package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shakibdshy/signet-auth"
)

func TestHandlerRejectsUnknownPaths(t *testing.T) {
	client, err := signet.New(completeConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/not-a-signet-route", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestMiddlewareComposes(t *testing.T) {
	client, err := signet.New(completeConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	client.OptionalAuth(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called || rec.Code != http.StatusNoContent {
		t.Errorf("OptionalAuth: called = %v, status = %d; want true and 204", called, rec.Code)
	}
	called = false
	rec = httptest.NewRecorder()
	client.RequireAuth(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if called || rec.Code != http.StatusUnauthorized {
		t.Errorf("RequireAuth: called = %v, status = %d; want false and 401", called, rec.Code)
	}
}

func TestUserFromContextWithoutUser(t *testing.T) {
	user, ok := signet.UserFromContext(context.Background())
	if ok || user != nil {
		t.Fatalf("UserFromContext() = (%v, %v), want (nil, false)", user, ok)
	}
}
