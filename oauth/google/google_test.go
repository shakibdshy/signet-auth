package google_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/oauth/google"
)

func TestProviderImplementsContractAndMapsIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_, _ = fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			_, _ = fmt.Fprint(w, `{"sub":"google-123","email":"user@example.com","email_verified":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := google.Provider{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		AuthEndpoint: server.URL + "/authorize",
		TokenURL:     server.URL + "/token",
		UserInfoURL:  server.URL + "/userinfo",
	}
	var _ signet.OAuthProvider = provider

	authURL := provider.AuthURL("client-id", "https://app.example.com/oauth/callback", "state-value", "challenge-value")
	for _, part := range []string{"state-value", "challenge-value", "client-id"} {
		if !strings.Contains(authURL, part) {
			t.Errorf("URL = %q, want %q", authURL, part)
		}
	}
	identity, err := provider.Exchange(context.Background(), "code", "verifier", "https://app.example.com/oauth/callback")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.Provider != "google" || identity.ProviderUserID != "google-123" ||
		identity.Email != "user@example.com" || !identity.EmailVerified {
		t.Errorf("identity = %+v", identity)
	}
}
