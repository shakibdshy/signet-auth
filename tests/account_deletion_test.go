package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/core"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

type failingAccountStore struct {
	*testutil.Store
}

func (s failingAccountStore) DeleteAccount(context.Context, string) error {
	return errors.New("delete account failed")
}

func deleteUserClient(t *testing.T, store core.Store) (*signet.Client, *testutil.Mailer) {
	t.Helper()
	mailer := &testutil.Mailer{}
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AppURL = "https://app.example.com"
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, mailer
}

func deleteUserSetup(t *testing.T, store core.Store) (*signet.Client, *testutil.Mailer, string) {
	t.Helper()
	client, mailer := deleteUserClient(t, store)
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "delete@example.com", Password: "correct horse", Name: "Ada"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := client.SignIn(ctx, signet.SignInInput{Email: "delete@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	return client, mailer, signUp.User.ID
}

func deleteTokenFromMail(t *testing.T, mailer *testutil.Mailer) string {
	t.Helper()
	if len(mailer.Messages) == 0 {
		t.Fatal("no deletion email captured")
	}
	body := mailer.Messages[0].TextBody
	i := strings.Index(body, "token=")
	if i < 0 {
		t.Fatalf("no token in email: %q", body)
	}
	raw := body[i+len("token="):]
	if j := strings.IndexAny(raw, " \n"); j >= 0 {
		raw = raw[:j]
	}
	return raw
}

func TestDeleteUserRemovesChildrenExplicitly(t *testing.T) {
	store := testutil.NewStore()
	client, mailer, userID := deleteUserSetup(t, store)
	ctx := context.Background()
	if err := client.RequestUserDeletion(ctx, signet.RequestDeleteUserInput{UserID: userID}); err != nil {
		t.Fatalf("RequestUserDeletion: %v", err)
	}
	raw := deleteTokenFromMail(t, mailer)
	if err := client.DeleteUser(ctx, signet.ConfirmDeleteUserInput{Token: raw}); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, ok := store.Users[userID]; ok {
		t.Error("User still present")
	}
	if len(store.Sessions) != 0 || len(store.Tokens) != 0 || len(store.Accounts) != 0 {
		t.Errorf("children remain: sessions=%d tokens=%d accounts=%d", len(store.Sessions), len(store.Tokens), len(store.Accounts))
	}
}

func TestDeleteUserRejectsBadTokensWithoutMutation(t *testing.T) {
	store := testutil.NewStore()
	client, _, userID := deleteUserSetup(t, store)
	ctx := context.Background()
	for _, token := range []string{"", "garbage"} {
		if err := client.DeleteUser(ctx, signet.ConfirmDeleteUserInput{Token: token}); !errors.Is(err, signet.ErrTokenInvalid) {
			t.Fatalf("token %q error = %v", token, err)
		}
	}
	if _, ok := store.Users[userID]; !ok {
		t.Error("User removed by invalid token")
	}
}

func TestDeleteUserFailureLeavesNoLiveSession(t *testing.T) {
	baseStore := testutil.NewStore()
	_, _, userID := deleteUserSetup(t, baseStore)
	ctx := context.Background()
	client, mailer := deleteUserClient(t, failingAccountStore{Store: baseStore})
	// Re-issue the deletion proof with the wrapped Store client's service.
	if err := client.RequestUserDeletion(ctx, signet.RequestDeleteUserInput{UserID: userID}); err != nil {
		t.Fatalf("RequestUserDeletion: %v", err)
	}
	raw := deleteTokenFromMail(t, mailer)
	if err := client.DeleteUser(ctx, signet.ConfirmDeleteUserInput{Token: raw}); err == nil {
		t.Fatal("expected DeleteAccount failure")
	}
	if _, ok := baseStore.Users[userID]; !ok {
		t.Error("User removed despite child deletion failure")
	}
	if len(baseStore.Sessions) != 0 {
		t.Errorf("live Sessions remain: %d", len(baseStore.Sessions))
	}
}

func TestDeleteUserHTTPEndpoints(t *testing.T) {
	store := testutil.NewStore()
	client, mailer, userID := deleteUserSetup(t, store)
	signInRec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(`{"email":"delete@example.com","password":"correct horse"}`))
	client.Handler().ServeHTTP(signInRec, req)
	if signInRec.Code != http.StatusOK {
		t.Fatalf("sign-in = %d %s", signInRec.Code, signInRec.Body.String())
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(signInRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode sign-in: %v", err)
	}
	post := func(path, payload string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
		for _, c := range signInRec.Result().Cookies() {
			r.AddCookie(c)
		}
		r.Header.Set("X-CSRF-Token", body.CSRFToken)
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		client.Handler().ServeHTTP(rec, r)
		return rec
	}
	if rec := post("/request-account-deletion", `{}`); rec.Code != http.StatusOK {
		t.Fatalf("request deletion = %d %s", rec.Code, rec.Body.String())
	}
	raw := deleteTokenFromMail(t, mailer)
	if rec := post("/confirm-account-deletion", `{"token":"`+raw+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("confirm deletion = %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := store.Users[userID]; ok {
		t.Error("User still present after HTTP deletion")
	}
}
