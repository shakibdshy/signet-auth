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

// hasSessionWithUserAgent lists Sessions over HTTP with the given cookie and
// reports whether one carries the expected user_agent.
func hasSessionWithUserAgent(t *testing.T, client *signet.Client, cookie *http.Cookie, want string) bool {
	t.Helper()
	for _, session := range listSessionsOverHTTP(t, client, cookie) {
		if session["user_agent"] == want {
			return true
		}
	}
	return false
}

// userAgentOfFirstSession lists Sessions over HTTP with the given cookie and
// returns the user_agent of the only Session.
func userAgentOfFirstSession(t *testing.T, client *signet.Client, cookie *http.Cookie) string {
	t.Helper()
	sessions := listSessionsOverHTTP(t, client, cookie)
	got, ok := sessions[0]["user_agent"].(string)
	if !ok {
		t.Fatalf("session user_agent missing or not a string")
	}
	return got
}

func getWithUserAgent(t *testing.T, client *signet.Client, path, userAgent string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	return rec
}

func TestMagicLinkVerificationRecordsUserAgent(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := client.SendMagicLink(ctx, signet.SendMagicLinkInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	rec := getWithUserAgent(t, client, "/verify-magic-link?token="+magicLinkTokenFromMail(t, mailer), testUserAgent)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /verify-magic-link status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if got := userAgentOfFirstSession(t, client, sessionCookieFromResponse(t, rec)); got != testUserAgent {
		t.Fatalf("magic-link Session user_agent = %#v, want %#v", got, testUserAgent)
	}
}

func TestEmailOTPVerificationRecordsUserAgent(t *testing.T) {
	client, _, mailer := passwordlessClient(t)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if err := client.SendEmailOTP(ctx, signet.SendEmailOTPInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendEmailOTP: %v", err)
	}
	code := otpCodeFromMail(t, mailer)
	req := httptest.NewRequest(http.MethodPost, "/verify-otp", strings.NewReader(`{"email":"user@example.com","code":"`+code+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", testUserAgent)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /verify-otp status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if got := userAgentOfFirstSession(t, client, sessionCookieFromResponse(t, rec)); got != testUserAgent {
		t.Fatalf("OTP Session user_agent = %#v, want %#v", got, testUserAgent)
	}
}

func TestSignUpAutoSignInRecordsUserAgent(t *testing.T) {
	store := testutil.NewStore()
	mailer := testutil.NewMailer()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AutoSignIn = &signet.AutoSignInConfig{AfterSignUp: true}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(`{"email":"user@example.com","password":"correct horse"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", testUserAgent)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /signup status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if got := userAgentOfFirstSession(t, client, sessionCookieFromResponse(t, rec)); got != testUserAgent {
		t.Fatalf("sign-up Session user_agent = %#v, want %#v", got, testUserAgent)
	}
}

func TestVerificationAutoSignInRecordsUserAgent(t *testing.T) {
	no := false
	client, mailer := autoSignInClient(t, false, true, &no, new(int), nil)
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/verify-email", strings.NewReader(`{"token":"`+verificationToken(t, mailer)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", testUserAgent)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /verify-email status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if got := userAgentOfFirstSession(t, client, sessionCookieFromResponse(t, rec)); got != testUserAgent {
		t.Fatalf("verification Session user_agent = %#v, want %#v", got, testUserAgent)
	}
}

func TestProgrammaticSignInRecordsEmptyUserAgent(t *testing.T) {
	client, _, _ := newAuthClient()
	if err := signUp(client); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(context.Background(), signet.SignInInput{Email: "user@example.com", Password: "password123"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	list, err := client.ListSessions(context.Background(), signet.ListSessionsInput{UserID: result.User.ID})
	if err != nil || len(list.Sessions) != 1 {
		t.Fatalf("ListSessions = (%v, %v)", list, err)
	}
	if got := list.Sessions[0].UserAgent; got != "" {
		t.Fatalf("programmatic Session UserAgent = %#v, want an empty string", got)
	}
}

func TestVerifyTwoFactorRecordsUserAgent(t *testing.T) {
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
	enabled := enableFactor(t, client, signUp.User.ID)
	if _, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{
		Challenge: enabled.Challenge, Code: totpCode(t, enabled.TOTPURI, totpTime),
	}); err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	challengeRec := postJSON(t, client, "/signin", `{"email":"user@example.com","password":"correct horse"}`)
	challenge := decodeBody(t, challengeRec)
	verifyReq := httptest.NewRequest(http.MethodPost, "/verify-two-factor",
		strings.NewReader(`{"challenge":"`+challenge["two_factor_challenge"].(string)+`","code":"`+totpCode(t, enabled.TOTPURI, totpTime)+`"}`))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("User-Agent", testUserAgent)
	verifyRec := httptest.NewRecorder()
	client.Handler().ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("POST /verify-two-factor status = %d; body = %s", verifyRec.Code, verifyRec.Body.String())
	}
	if !hasSessionWithUserAgent(t, client, sessionCookieFromResponse(t, verifyRec), testUserAgent) {
		t.Fatal("no Session carries the verify-two-factor request's user agent")
	}
}

func TestPasskeyFinishRecordsUserAgent(t *testing.T) {
	protocol := &fakePasskeyProtocol{}
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Passkeys = &signet.PasskeysConfig{
		RPID: "example.com", RPOrigins: []string{"https://example.com"},
		Store: newFakePasskeyStore(), Protocol: protocol,
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	userID, _ := passkeyUser(t, client)
	protocol.userID = userID
	ctx := context.Background()
	begin, err := client.BeginPasskeySignIn(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/passkeys/signin-finish",
		strings.NewReader(`{"token":"`+begin.Token+`","response":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", testUserAgent)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /passkeys/signin-finish status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if !hasSessionWithUserAgent(t, client, sessionCookieFromResponse(t, rec), testUserAgent) {
		t.Fatal("no Session carries the passkey finish request's user agent")
	}
}

func TestOAuthCallbackRecordsUserAgent(t *testing.T) {
	client, _ := oauthCallbackClient(t, fakeOAuthProvider{name: "google"})
	state := startOAuth(t, client)
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=code&state="+url.QueryEscape(state), nil)
	req.Header.Set("User-Agent", testUserAgent)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got := userAgentOfFirstSession(t, client, sessionCookieFromResponse(t, rec)); got != testUserAgent {
		t.Fatalf("OAuth Session user_agent = %#v, want %#v", got, testUserAgent)
	}
}

func TestSSOCallbackRecordsUserAgent(t *testing.T) {
	provider := &fakeSSOProvider{identity: &signet.OAuthIdentity{
		ProviderUserID: "subject-ua", Email: "ua@acme.com", EmailVerified: true,
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
	startReq := httptest.NewRequest(http.MethodPost, "/sso/start", strings.NewReader(`{"email":"ua@acme.com"}`))
	rr = httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, startReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("start status = %d body = %s", rr.Code, rr.Body.String())
	}
	var start struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &start); err != nil || start.State == "" {
		t.Fatalf("decode = %v body = %s", err, rr.Body.String())
	}
	callbackReq := httptest.NewRequest(http.MethodGet, "/sso/callback?state="+start.State+"&code=code", nil)
	callbackReq.Header.Set("User-Agent", testUserAgent)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, callbackReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback status = %d body = %s", rec.Code, rec.Body.String())
	}
	if got := userAgentOfFirstSession(t, client, sessionCookieFromResponse(t, rec)); got != testUserAgent {
		t.Fatalf("SSO Session user_agent = %#v, want %#v", got, testUserAgent)
	}
}

func TestSAMLACSRecordsUserAgent(t *testing.T) {
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
		NameID: "saml-subject-ua", InResponseTo: start.RequestID,
		Recipient: "https://app.example.com/saml/acs", AudienceRestrictions: []string{spEntityID},
		Attributes: []types.Attribute{{
			Name: "email", Values: []types.AttributeValue{{Value: "ua@acme.com"}},
		}, {
			Name: "email_verified", Values: []types.AttributeValue{{Value: "true"}},
		}},
	})
	if err != nil {
		t.Fatalf("assertion: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(mustBytes(document.WriteToBytes()))
	form := url.Values{"SAMLResponse": {encoded}, "state": {start.State}}
	request := httptest.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", testUserAgent)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, request)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /saml/acs status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if got := userAgentOfFirstSession(t, client, sessionCookieFromResponse(t, rec)); got != testUserAgent {
		t.Fatalf("SAML Session user_agent = %#v, want %#v", got, testUserAgent)
	}
}

func TestImpersonationRecordsUserAgent(t *testing.T) {
	client, _, adminID, token := adminFixture(t, &adminAuditSink{})
	ctx := context.Background()
	users, _ := client.AdminListUsers(ctx, signet.AdminListUsersInput{ActorID: adminID, SessionToken: token})
	var targetID string
	for _, user := range users.Users {
		if user.Email == "target@example.com" {
			targetID = user.ID
		}
	}
	started, err := client.ImpersonateUser(ctx, signet.ImpersonateUserInput{
		ActorID: adminID, SessionToken: token, UserID: targetID, UserAgent: testUserAgent,
	})
	if err != nil {
		t.Fatalf("ImpersonateUser: %v", err)
	}
	list, err := client.ListSessions(ctx, signet.ListSessionsInput{UserID: targetID})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	found := false
	for _, session := range list.Sessions {
		if session.ID != "" && session.UserAgent == testUserAgent {
			found = true
		}
	}
	if !found {
		t.Fatalf("no impersonation Session carries the admin's user agent (token resolves: %v)", client.VerifyFreshSession(ctx, started.Token) == nil)
	}
}

func TestTokenPasswordGrantRecordsUserAgent(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.JWT = &signet.JWTConfig{Algorithm: "HS256", Key: []byte("jwt-key-123456789012345678901234")}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"email":"user@example.com","password":"correct horse"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", testUserAgent)
	rec := httptest.NewRecorder()
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var pair struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pair); err != nil || pair.AccessToken == "" {
		t.Fatalf("token pair = %s", rec.Body.String())
	}
	user, err := client.VerifyAccessToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	list, err := client.ListSessions(ctx, signet.ListSessionsInput{UserID: user.ID})
	if err != nil || len(list.Sessions) == 0 {
		t.Fatalf("ListSessions = (%v, %v)", list, err)
	}
	for _, session := range list.Sessions {
		if session.UserAgent != testUserAgent {
			t.Fatalf("grant Session user_agent = %#v, want %#v", session.UserAgent, testUserAgent)
		}
	}
}
