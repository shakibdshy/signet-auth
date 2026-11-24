package github_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/oauth/github"
)

func TestProviderImplementsContractAndMapsVerifiedEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_, _ = fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/user":
			_, _ = fmt.Fprint(w, `{"id":12345,"login":"octocat"}`)
		case "/emails":
			_, _ = fmt.Fprint(w, `[{"email":"other@example.com","primary":false,"verified":true},{"email":"user@example.com","primary":true,"verified":true}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := github.Provider{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		AuthEndpoint: server.URL + "/authorize",
		TokenURL:     server.URL + "/token",
		UserInfoURL:  server.URL + "/user",
		EmailsURL:    server.URL + "/emails",
	}
	var _ signet.OAuthProvider = provider

	identity, err := provider.Exchange(context.Background(), "code", "verifier", "https://app.example.com/oauth/callback")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Provider != "github" || identity.ProviderUserID != "12345" ||
		identity.Email != "user@example.com" || !identity.EmailVerified {
		t.Errorf("identity = %+v", identity)
	}
}

func TestProviderTreatsUnverifiedEmailAsUnverified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_, _ = fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer"}`)
		case "/user":
			_, _ = fmt.Fprint(w, `{"id":12345}`)
		case "/emails":
			_, _ = fmt.Fprint(w, `[{"email":"user@example.com","primary":true,"verified":false}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := github.Provider{
		ClientID: "id", ClientSecret: "secret",
		AuthEndpoint: server.URL + "/authorize", TokenURL: server.URL + "/token",
		UserInfoURL: server.URL + "/user", EmailsURL: server.URL + "/emails",
	}
	identity, err := provider.Exchange(context.Background(), "code", "verifier", "https://app.example.com/oauth/callback")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.EmailVerified {
		t.Error("unverified primary email must not be reported as verified")
	}
}
