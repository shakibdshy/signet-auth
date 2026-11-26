package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

func lastMethodValue(t *testing.T, client *signet.Client, responses ...*httptest.ResponseRecorder) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/last-sign-in-method", nil)
	for _, rec := range responses {
		if cookie := cookieValue(rec); cookie != nil {
			req.AddCookie(cookie)
		}
	}
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /last-sign-in-method status = %d", rec.Code)
	}
	var body struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET /last-sign-in-method body = %s", rec.Body.String())
	}
	return body.Method
}

func postJSON(t *testing.T, client *signet.Client, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body = %s", rec.Body.String())
	}
	return body
}

func TestPasswordSignInReportsMethodInBodyAndCookie(t *testing.T) {
	client := lastMethodClient(t, nil)
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec := postJSON(t, client, "/signin", `{"email":"user@example.com","password":"correct horse"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /signin status = %d; body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if got, ok := body["last_sign_in_method"].(string); !ok || got != "password" {
		t.Fatalf("sign-in body last_sign_in_method = %#v, want \"password\"", body["last_sign_in_method"])
	}
	if cookieValue(rec) == nil {
		t.Fatal("sign-in wrote no last-method cookie")
	}
	if got := lastMethodValue(t, client, rec); got != "password" {
		t.Fatalf("GET /last-sign-in-method = %#v, want \"password\"", got)
	}
}

func TestUsernameSignInReportsPassword(t *testing.T) {
	client := lastMethodClient(t, nil)
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse", Username: "ada",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec := postJSON(t, client, "/signin", `{"username":"ada","password":"correct horse"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /signin status = %d; body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if got, ok := body["last_sign_in_method"].(string); !ok || got != "password" {
		t.Fatalf("username sign-in last_sign_in_method = %#v, want \"password\"", body["last_sign_in_method"])
	}
	if got := lastMethodValue(t, client, rec); got != "password" {
		t.Fatalf("GET /last-sign-in-method = %#v, want \"password\"", got)
	}
}

func TestTwoFactorChallengeWritesNoCookie(t *testing.T) {
	totpTime := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	client := lastMethodClient(t, func(cfg *signet.Config) {
		cfg.TOTPStore = newFakeTOTPStore()
		cfg.TOTPKey = []byte("0123456789abcdef0123456789abcdef")
		cfg.Clock = &testutil.Clock{At: totpTime}
	})
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	// A completed password sign-in records the method first.
	rec := postJSON(t, client, "/signin", `{"email":"user@example.com","password":"correct horse"}`)
	if rec.Code != http.StatusOK || cookieValue(rec) == nil {
		t.Fatalf("first sign-in should write the cookie; status = %d", rec.Code)
	}
	enabled := enableFactor(t, client, signUp.User.ID)
	// Enrollment stays pending until confirmed; confirm before sign-in issues challenges.
	if _, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{
		Challenge: enabled.Challenge, Code: totpCode(t, enabled.TOTPURI, totpTime),
	}); err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}

	challengeRec := postJSON(t, client, "/signin", `{"email":"user@example.com","password":"correct horse"}`)
	if challengeRec.Code != http.StatusOK {
		t.Fatalf("challenge sign-in status = %d; body = %s", challengeRec.Code, challengeRec.Body.String())
	}
	challenge := decodeBody(t, challengeRec)
	if challenge["two_factor_challenge"] == "" {
		t.Fatalf("expected a challenge: %s", challengeRec.Body.String())
	}
	if cookie := cookieValue(challengeRec); cookie != nil {
		t.Fatalf("the Two-factor challenge must not write the last-method cookie, got %q", cookie.Value)
	}
	if got := lastMethodValue(t, client, rec); got != "password" {
		t.Fatalf("GET /last-sign-in-method = %#v, want the previous \"password\"", got)
	}

	code := totpCode(t, enabled.TOTPURI, totpTime)
	verifyRec := postJSON(t, client, "/verify-two-factor", `{"challenge":"`+challenge["two_factor_challenge"].(string)+`","code":"`+code+`"}`)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("POST /verify-two-factor status = %d; body = %s", verifyRec.Code, verifyRec.Body.String())
	}
	verifyBody := decodeBody(t, verifyRec)
	if got, ok := verifyBody["last_sign_in_method"].(string); !ok || got != "password" {
		t.Fatalf("verify-two-factor body last_sign_in_method = %#v, want \"password\"", verifyBody["last_sign_in_method"])
	}
	if got := lastMethodValue(t, client, verifyRec); got != "password" {
		t.Fatalf("after verify-two-factor GET /last-sign-in-method = %#v, want \"password\"", got)
	}
}

func TestTokenPasswordGrantReportsMethod(t *testing.T) {
	client := lastMethodClient(t, func(cfg *signet.Config) {
		cfg.JWT = &signet.JWTConfig{Algorithm: "HS256", Key: []byte("jwt-key-123456789012345678901234")}
	})
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec := postJSON(t, client, "/token", `{"email":"user@example.com","password":"correct horse"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token status = %d; body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if got, ok := body["last_sign_in_method"].(string); !ok || got != "password" {
		t.Fatalf("token grant last_sign_in_method = %#v, want \"password\"", body["last_sign_in_method"])
	}
}

func TestSignInReportsMethodWhenFeatureDisabled(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec := postJSON(t, client, "/signin", `{"email":"user@example.com","password":"password123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /signin status = %d; body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if got, ok := body["last_sign_in_method"].(string); !ok || got != "password" {
		t.Fatalf("sign-in body last_sign_in_method = %#v, want \"password\" even with the cookie disabled", body["last_sign_in_method"])
	}
	if cookie := cookieValue(rec); cookie != nil {
		t.Fatalf("no cookie must be written while the feature is disabled, got %q", cookie.Value)
	}
	if got := lastMethodValue(t, client); got != "" {
		t.Fatalf("GET /last-sign-in-method = %#v, want an empty string while disabled", got)
	}
}
