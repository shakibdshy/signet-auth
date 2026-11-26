package tests

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	samlidp "github.com/russellhaering/gosaml2/v2/idp"
	"github.com/russellhaering/gosaml2/v2/types"
	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

// lastMethodClientAndMailer builds a client with the Last sign-in method
// cookie enabled and returns the mailer so tests can read proof emails.
func lastMethodClientAndMailer(t *testing.T, configure func(*signet.Config)) (*signet.Client, *testutil.Mailer) {
	t.Helper()
	mailer := testutil.NewMailer()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.LastSignInMethod = &signet.LastSignInMethodConfig{}
	if configure != nil {
		configure(&cfg)
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, mailer
}

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

func TestMagicLinkSignInReportsCanonicalMethod(t *testing.T) {
	client, mailer := lastMethodClientAndMailer(t, func(cfg *signet.Config) {
		cfg.AppURL = "https://app.example.com"
	})
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	token := magicLinkTokenFromMail(t, mailer)
	rec := getWithTestUserAgent(t, client, "/verify-magic-link?token="+token)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /verify-magic-link status = %d; body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if got, ok := body["last_sign_in_method"].(string); !ok || got != "magic_link" {
		t.Fatalf("magic-link body last_sign_in_method = %#v, want \"magic_link\"", body["last_sign_in_method"])
	}
	if got := lastMethodValue(t, client, rec); got != "magic_link" {
		t.Fatalf("GET /last-sign-in-method = %#v, want \"magic_link\"", got)
	}
}

func TestEmailOTPSignInReportsCanonicalMethod(t *testing.T) {
	client, mailer := lastMethodClientAndMailer(t, nil)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	rec := postJSON(t, client, "/verify-otp", `{"email":"user@example.com","code":"`+code+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /verify-otp status = %d; body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if got, ok := body["last_sign_in_method"].(string); !ok || got != "otp" {
		t.Fatalf("OTP body last_sign_in_method = %#v, want \"otp\"", body["last_sign_in_method"])
	}
	if got := lastMethodValue(t, client, rec); got != "otp" {
		t.Fatalf("GET /last-sign-in-method = %#v, want \"otp\"", got)
	}
}

func TestSignUpAutoSignInReportsBackingFactor(t *testing.T) {
	client := lastMethodClient(t, func(cfg *signet.Config) {
		cfg.AutoSignIn = &signet.AutoSignInConfig{AfterSignUp: true}
	})
	rec := postJSON(t, client, "/signup", `{"email":"user@example.com","password":"correct horse"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /signup status = %d; body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["session_token"] == "" {
		t.Fatal("expected a session token from automatic sign-in")
	}
	if got, ok := body["last_sign_in_method"].(string); !ok || got != "password" {
		t.Fatalf("sign-up body last_sign_in_method = %#v, want \"password\"", body["last_sign_in_method"])
	}
	if got := lastMethodValue(t, client, rec); got != "password" {
		t.Fatalf("GET /last-sign-in-method = %#v, want \"password\"", got)
	}

	// Without automatic sign-in there is no Session, so no method either.
	plain := lastMethodClient(t, nil)
	noSession := postJSON(t, plain, "/signup", `{"email":"other@example.com","password":"correct horse"}`)
	if noSession.Code != http.StatusCreated {
		t.Fatalf("POST /signup status = %d", noSession.Code)
	}
	plainBody := decodeBody(t, noSession)
	if _, ok := plainBody["last_sign_in_method"]; ok {
		t.Fatal("sign-up without a Session must not report a sign-in method")
	}
	if cookie := cookieValue(noSession); cookie != nil {
		t.Fatal("sign-up without a Session must not write the cookie")
	}
}

func TestVerificationAutoSignInReportsMagicLink(t *testing.T) {
	no := false
	client, mailer := autoSignInClient(t, false, true, &no, new(int), nil)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rec := postJSON(t, client, "/verify-email", `{"token":"`+verificationToken(t, mailer)+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /verify-email status = %d; body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["session_token"] == "" {
		t.Fatal("expected a session token from automatic sign-in")
	}
	if got, ok := body["last_sign_in_method"].(string); !ok || got != "magic_link" {
		t.Fatalf("verification body last_sign_in_method = %#v, want \"magic_link\"", body["last_sign_in_method"])
	}
	if got := lastMethodValue(t, client, rec); got != "magic_link" {
		t.Fatalf("GET /last-sign-in-method = %#v, want \"magic_link\"", got)
	}
}

func TestSSOCallbackReportsMethod(t *testing.T) {
	provider := &fakeSSOProvider{identity: &signet.OAuthIdentity{
		ProviderUserID: "subject-m", Email: "method@acme.com", EmailVerified: true,
	}}
	client, token, orgID := ssoClient(t, provider, verifyTrue)
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	cookies := &http.Cookie{Name: "__Host-signet_session", Value: token, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	createReq := httptest.NewRequest(http.MethodPost, "/sso/connections",
		strings.NewReader(`{"organization_id":"`+orgID+`","issuer":"https://idp.example.com","domains":["acme.com"]}`))
	createReq.AddCookie(cookies)
	createReq.AddCookie(csrfCookie)
	createReq.Header.Set("X-CSRF-Token", csrfToken)
	rr := httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, createReq)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", rr.Code, rr.Body.String())
	}
	startReq := httptest.NewRequest(http.MethodPost, "/sso/start", strings.NewReader(`{"email":"method@acme.com"}`))
	rr = httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, startReq)
	var start struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &start); err != nil || start.State == "" {
		t.Fatalf("decode = %v body = %s", err, rr.Body.String())
	}
	rec := getWithTestUserAgent(t, client, "/sso/callback?state="+start.State+"&code=code")
	if rec.Code != http.StatusOK {
		t.Fatalf("callback status = %d body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if got, ok := body["last_sign_in_method"].(string); !ok || got != "sso" {
		t.Fatalf("SSO body last_sign_in_method = %#v, want \"sso\"", body["last_sign_in_method"])
	}
}

func TestSAMLACSReportsMethod(t *testing.T) {
	client, token, orgID := samlClient(t)
	ctx := context.Background()
	spEntityID := "https://app.example.com/saml/metadata"
	idpServer := newLocalSAMLIdP(t)
	idpServer.idp.ServiceProviders[spEntityID] = &samlidp.SPConfig{}
	if _, err := client.CreateSSOConnection(ctx, signet.CreateSSOConnectionInput{
		OrganizationID: orgID, Protocol: "saml", Issuer: "https://idp.example.com",
		Domains: []string{"acme.com"}, Metadata: idpServer.metadata, SessionToken: token,
	}); err != nil {
		t.Fatalf("connection: %v", err)
	}
	start, err := client.StartSAMLSignIn(ctx, signet.SAMLStartInput{OrganizationID: orgID})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	document, _, err := idpServer.idp.BuildResponseDocument(spEntityID, &samlidp.AssertionParams{
		NameID: "saml-method", InResponseTo: start.RequestID,
		Recipient: "https://app.example.com/saml/acs", AudienceRestrictions: []string{spEntityID},
		Attributes: []types.Attribute{{
			Name: "email", Values: []types.AttributeValue{{Value: "method@acme.com"}},
		}, {
			Name: "email_verified", Values: []types.AttributeValue{{Value: "true"}},
		}},
	})
	if err != nil {
		t.Fatalf("assertion: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(mustBytes(document.WriteToBytes()))
	form := url.Values{"SAMLResponse": {encoded}, "state": {start.State}}
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /saml/acs status = %d; body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if got, ok := body["last_sign_in_method"].(string); !ok || got != "saml" {
		t.Fatalf("SAML body last_sign_in_method = %#v, want \"saml\"", body["last_sign_in_method"])
	}
}

func TestOAuthCallbackRecordsGenericMethod(t *testing.T) {
	client := lastMethodClient(t, func(cfg *signet.Config) {
		cfg.OAuth = &signet.OAuthConfig{
			Providers:        []signet.OAuthProvider{fakeOAuthProvider{name: "google"}},
			RedirectBaseURL:  "https://app.example.com",
			AllowedRedirects: []string{"https://app.example.com/dashboard"},
			StateKey:         make([]byte, 32),
		}
	})
	state := startOAuth(t, client)
	rec := getWithTestUserAgent(t, client, "/oauth/callback?code=code&state="+url.QueryEscape(state))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got := lastMethodValue(t, client, rec); got != "oauth" {
		t.Fatalf("GET /last-sign-in-method = %#v, want \"oauth\", not the provider name", got)
	}
	result, err := client.OAuthCallback(context.Background(), signet.OAuthCallbackInput{Code: "code2", State: state})
	if err == nil && result.User != nil {
		t.Fatalf("replayed state should fail, got %+v", result)
	}
}
