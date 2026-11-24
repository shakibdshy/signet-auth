package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet-auth"
	"github.com/shakibdshy/signet-auth/internal/testutil"
)

const passkeyCredentialID = "cred-" + "ential-1"

type fakePasskeyStore struct {
	credentials map[string]*signet.WebAuthnCredential
}

func newFakePasskeyStore() *fakePasskeyStore {
	return &fakePasskeyStore{credentials: make(map[string]*signet.WebAuthnCredential)}
}

func (s *fakePasskeyStore) CreateCredential(_ context.Context, c *signet.WebAuthnCredential) error {
	clone := *c
	s.credentials[c.ID] = &clone
	return nil
}
func (s *fakePasskeyStore) CredentialsByUser(_ context.Context, userID string) ([]*signet.WebAuthnCredential, error) {
	out := make([]*signet.WebAuthnCredential, 0)
	for _, c := range s.credentials {
		if c.UserID == userID {
			clone := *c
			out = append(out, &clone)
		}
	}
	return out, nil
}
func (s *fakePasskeyStore) CredentialByID(_ context.Context, id string) (*signet.WebAuthnCredential, error) {
	c, ok := s.credentials[id]
	if !ok {
		return nil, signet.ErrNotFound
	}
	clone := *c
	return &clone, nil
}
func (s *fakePasskeyStore) UpdateCredential(_ context.Context, c *signet.WebAuthnCredential) error {
	clone := *c
	s.credentials[c.ID] = &clone
	return nil
}
func (s *fakePasskeyStore) DeleteCredential(_ context.Context, id string) error {
	delete(s.credentials, id)
	return nil
}

type fakePasskeyProtocol struct {
	beginCalls   int
	finishCalls  int
	loginCalls   int
	assertCalls  int
	credentialID string
	userID       string
	failFinish   bool
}

func (p *fakePasskeyProtocol) BeginRegistration(_ context.Context, _, _ string, _ []*signet.WebAuthnCredential) ([]byte, string, error) {
	p.beginCalls++
	return json.RawMessage(`{"challenge":"reg"}`), "registration-data", nil
}
func (p *fakePasskeyProtocol) FinishRegistration(_ context.Context, data string, _ []byte) (*signet.WebAuthnCredential, error) {
	p.finishCalls++
	if p.failFinish || data != "registration-data" {
		return nil, errors.New("bad ceremony data")
	}
	id := p.credentialID
	if id == "" {
		id = passkeyCredentialID
	}
	return &signet.WebAuthnCredential{ID: id, AAGUID: "aaguid", PublicKey: []byte("key")}, nil
}
func (p *fakePasskeyProtocol) BeginLogin(_ context.Context) ([]byte, string, error) {
	p.loginCalls++
	return json.RawMessage(`{"challenge":"login"}`), "login-data", nil
}
func (p *fakePasskeyProtocol) FinishLogin(_ context.Context, data string, _ []byte) (string, *signet.WebAuthnCredential, error) {
	p.assertCalls++
	if data != "login-data" {
		return "", nil, errors.New("bad ceremony data")
	}
	id := p.credentialID
	if id == "" {
		id = passkeyCredentialID
	}
	userID := p.userID
	if userID == "" {
		userID = "user-1"
	}
	return userID, &signet.WebAuthnCredential{ID: id, AAGUID: "aaguid"}, nil
}

func passkeyClient(t *testing.T, store *fakePasskeyStore, protocol signet.PasskeyProtocol) (*signet.Client, signet.Config) {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Passkeys = &signet.PasskeysConfig{
		RPID: "example.com", RPOrigins: []string{"https://example.com"},
		Store: store, Protocol: protocol,
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, cfg
}

func passkeyUser(t *testing.T, client *signet.Client) (string, string) {
	t.Helper()
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	return signUp.User.ID, result.SessionToken
}

func TestPasskeyEnrollmentAndListing(t *testing.T) {
	store := newFakePasskeyStore()
	protocol := &fakePasskeyProtocol{}
	client, _ := passkeyClient(t, store, protocol)
	userID, token := passkeyUser(t, client)
	ctx := context.Background()
	ceremony, err := client.BeginPasskeyRegistration(ctx, signet.PasskeyRegistrationInput{
		UserID: userID, SessionToken: token,
	})
	if err != nil || ceremony.Token == "" || len(ceremony.Options) == 0 {
		t.Fatalf("begin = %+v err = %v", ceremony, err)
	}
	if err := client.FinishPasskeyRegistration(ctx, signet.PasskeyFinishInput{
		Token: ceremony.Token, Response: json.RawMessage(`{}`), SessionToken: token,
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	list, err := client.ListPasskeys(ctx, signet.PasskeyListInput{UserID: userID, SessionToken: token})
	if err != nil || len(list.Passkeys) != 1 || list.Passkeys[0].AAGUID != "aaguid" {
		t.Fatalf("list = %+v err = %v", list, err)
	}
	if _, ok := store.credentials[passkeyCredentialID]; !ok {
		t.Fatal("credential not stored")
	}
}

func TestPasskeyRegistrationReplayRejected(t *testing.T) {
	store := newFakePasskeyStore()
	client, _ := passkeyClient(t, store, &fakePasskeyProtocol{})
	userID, token := passkeyUser(t, client)
	ctx := context.Background()
	ceremony, err := client.BeginPasskeyRegistration(ctx, signet.PasskeyRegistrationInput{
		UserID: userID, SessionToken: token,
	})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	in := signet.PasskeyFinishInput{Token: ceremony.Token, Response: json.RawMessage(`{}`), SessionToken: token}
	if err := client.FinishPasskeyRegistration(ctx, in); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if err := client.FinishPasskeyRegistration(ctx, in); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestPasskeyEnrollmentRequiresFreshSession(t *testing.T) {
	client, _ := passkeyClient(t, newFakePasskeyStore(), &fakePasskeyProtocol{})
	userID, _ := passkeyUser(t, client)
	_, err := client.BeginPasskeyRegistration(context.Background(), signet.PasskeyRegistrationInput{
		UserID: userID, SessionToken: "stale",
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("stale enrollment error = %v", err)
	}
}

func TestPasskeySignInCreatesSession(t *testing.T) {
	store := newFakePasskeyStore()
	protocol := &fakePasskeyProtocol{}
	client, _ := passkeyClient(t, store, protocol)
	userID, _ := passkeyUser(t, client)
	protocol.userID = userID
	ctx := context.Background()
	begin, err := client.BeginPasskeySignIn(ctx)
	if err != nil || begin.Token == "" {
		t.Fatalf("begin = %+v err = %v", begin, err)
	}
	result, err := client.FinishPasskeySignIn(ctx, signet.PasskeyFinishSignInInput{
		Token: begin.Token, Response: json.RawMessage(`{}`),
	})
	if err != nil || result.SessionToken == "" || result.LastSignInMethod != "passkey" {
		t.Fatalf("result = %+v err = %v", result, err)
	}
	if err := client.VerifyFreshSession(ctx, result.SessionToken); err != nil {
		t.Fatalf("session not valid: %v", err)
	}
}

func TestPasskeySignInReplayRejected(t *testing.T) {
	protocol := &fakePasskeyProtocol{}
	client, _ := passkeyClient(t, newFakePasskeyStore(), protocol)
	userID, _ := passkeyUser(t, client)
	protocol.userID = userID
	ctx := context.Background()
	begin, err := client.BeginPasskeySignIn(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	in := signet.PasskeyFinishSignInInput{Token: begin.Token, Response: json.RawMessage(`{}`)}
	if _, err := client.FinishPasskeySignIn(ctx, in); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if _, err := client.FinishPasskeySignIn(ctx, in); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestPasskeyCeremonyExpiry(t *testing.T) {
	clock := &testutil.Clock{At: time.Now()}
	store := newFakePasskeyStore()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Clock = clock
	cfg.Accounts = &signet.AccountConfig{FreshWindow: time.Hour}
	cfg.Passkeys = &signet.PasskeysConfig{
		RPID: "example.com", RPOrigins: []string{"https://example.com"},
		Store: store, Protocol: &fakePasskeyProtocol{},
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	userID, token := passkeyUser(t, client)
	begin, err := client.BeginPasskeyRegistration(ctx, signet.PasskeyRegistrationInput{
		UserID: userID, SessionToken: token,
	})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	clock.At = clock.At.Add(10 * time.Minute)
	if err := client.FinishPasskeyRegistration(ctx, signet.PasskeyFinishInput{
		Token: begin.Token, Response: json.RawMessage(`{}`), SessionToken: token,
	}); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("expired ceremony error = %v", err)
	}
}

func TestPasskeyDisabled(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.BeginPasskeySignIn(context.Background()); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("disabled error = %v", err)
	}
}

func TestPasskeysConfigValidation(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Passkeys = &signet.PasskeysConfig{RPID: "example.com"}
	if _, err := signet.New(cfg); !errors.Is(err, signet.ErrInvalidPasskeysConfig) {
		t.Fatalf("validation error = %v", err)
	}
}

func TestPasskeyDeleteOwnerScoped(t *testing.T) {
	store := newFakePasskeyStore()
	client, _ := passkeyClient(t, store, &fakePasskeyProtocol{})
	userID, token := passkeyUser(t, client)
	ctx := context.Background()
	begin, err := client.BeginPasskeyRegistration(ctx, signet.PasskeyRegistrationInput{
		UserID: userID, SessionToken: token,
	})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := client.FinishPasskeyRegistration(ctx, signet.PasskeyFinishInput{
		Token: begin.Token, Response: json.RawMessage(`{}`), SessionToken: token,
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if err := client.DeletePasskey(ctx, signet.PasskeyDeleteInput{
		UserID: "other", CredentialID: passkeyCredentialID, SessionToken: token,
	}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("cross-owner delete error = %v", err)
	}
	if err := client.DeletePasskey(ctx, signet.PasskeyDeleteInput{
		UserID: userID, CredentialID: passkeyCredentialID, SessionToken: "stale",
	}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("stale delete error = %v", err)
	}
	if err := client.DeletePasskey(ctx, signet.PasskeyDeleteInput{
		UserID: userID, CredentialID: passkeyCredentialID, SessionToken: token,
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestPasskeyHTTPEndpoints(t *testing.T) {
	store := newFakePasskeyStore()
	protocol := &fakePasskeyProtocol{}
	client, _ := passkeyClient(t, store, protocol)
	userID, token := passkeyUser(t, client)
	protocol.userID = userID
	cookies := &http.Cookie{Name: "__Host-signet_session", Value: token, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	post := func(path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.AddCookie(cookies)
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfToken)
		client.Handler().ServeHTTP(rr, req)
		return rr
	}
	begin := post("/passkeys/register-begin", `{"user_id":"`+userID+`"}`)
	if begin.Code != http.StatusOK || !strings.Contains(begin.Body.String(), "token") {
		t.Fatalf("register begin = %d %s", begin.Code, begin.Body.String())
	}
	var ceremony struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &ceremony); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rr := post("/passkeys/register-finish", `{"token":"`+ceremony.Token+`","response":{}}`); rr.Code != http.StatusOK {
		t.Fatalf("register finish = %d %s", rr.Code, rr.Body.String())
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/passkeys", nil)
	req.AddCookie(cookies)
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), passkeyCredentialID) {
		t.Fatalf("list = %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("/passkeys/delete", `{"credential_id":"`+passkeyCredentialID+`"}`); rr.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rr.Code, rr.Body.String())
	}

	signInBegin := httptest.NewRecorder()
	client.Handler().ServeHTTP(signInBegin, httptest.NewRequest(http.MethodPost, "/passkeys/signin-begin", nil))
	if signInBegin.Code != http.StatusOK {
		t.Fatalf("signin begin = %d %s", signInBegin.Code, signInBegin.Body.String())
	}
	if err := json.Unmarshal(signInBegin.Body.Bytes(), &ceremony); err != nil {
		t.Fatalf("decode: %v", err)
	}
	signInFinish := httptest.NewRecorder()
	client.Handler().ServeHTTP(signInFinish, httptest.NewRequest(http.MethodPost, "/passkeys/signin-finish",
		strings.NewReader(`{"token":"`+ceremony.Token+`","response":{}}`)))
	if signInFinish.Code != http.StatusOK || !strings.Contains(signInFinish.Body.String(), "passkey") {
		t.Fatalf("signin finish = %d %s", signInFinish.Code, signInFinish.Body.String())
	}
}

func TestPasskeyOnlyUserCanSetPassword(t *testing.T) {
	protocol := &fakePasskeyProtocol{}
	client, cfg := passkeyClient(t, newFakePasskeyStore(), protocol)
	userID, _ := passkeyUser(t, client)
	cfg.AppURL = "https://app.example.com"
	store := cfg.Store.(*testutil.Store)
	// Simulate a passkey-only User: no credential Account.
	for _, account := range store.Accounts {
		if account.UserID == userID {
			_ = store.DeleteAccount(context.Background(), account.ID)
		}
	}
	ctx := context.Background()
	if err := client.SendPasswordReset(ctx, signet.SendPasswordResetInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}
	mailer := cfg.Mailer.(*testutil.Mailer)
	body := mailer.Messages[len(mailer.Messages)-1].TextBody
	i := strings.Index(body, "token=")
	if i < 0 {
		t.Fatalf("no token in email: %q", body)
	}
	raw := body[i+len("token="):]
	if j := strings.IndexAny(raw, " \n&"); j >= 0 {
		raw = raw[:j]
	}
	if err := client.ResetPassword(ctx, signet.ResetPasswordInput{Token: raw, NewPassword: "new correct horse"}); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if result, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "new correct horse"}); err != nil || result.SessionToken == "" {
		t.Fatalf("sign in with new password = %+v err = %v", result, err)
	}
}

func TestEmailChangeAcceptsFreshPasskeySession(t *testing.T) {
	client, _ := passkeyClient(t, newFakePasskeyStore(), &fakePasskeyProtocol{})
	userID, token := passkeyUser(t, client)
	err := client.RequestEmailChange(context.Background(), signet.ChangeEmailInput{
		UserID: userID, SessionToken: token, NewEmail: "new@example.com",
	})
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
}

func TestEmailChangeRejectsStaleSession(t *testing.T) {
	client, _ := passkeyClient(t, newFakePasskeyStore(), &fakePasskeyProtocol{})
	userID, _ := passkeyUser(t, client)
	err := client.RequestEmailChange(context.Background(), signet.ChangeEmailInput{
		UserID: userID, SessionToken: "stale", NewEmail: "new@example.com",
	})
	if !errors.Is(err, signet.ErrInvalidCredentials) {
		t.Fatalf("stale email change error = %v", err)
	}
}

func TestUserDeletionRemovesPasskeys(t *testing.T) {
	store := newFakePasskeyStore()
	client, cfg := passkeyClient(t, store, &fakePasskeyProtocol{})
	userID, token := passkeyUser(t, client)
	ctx := context.Background()
	begin, err := client.BeginPasskeyRegistration(ctx, signet.PasskeyRegistrationInput{
		UserID: userID, SessionToken: token,
	})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := client.FinishPasskeyRegistration(ctx, signet.PasskeyFinishInput{
		Token: begin.Token, Response: json.RawMessage(`{}`), SessionToken: token,
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if err := client.RequestUserDeletion(ctx, signet.RequestDeleteUserInput{UserID: userID}); err != nil {
		t.Fatalf("RequestUserDeletion: %v", err)
	}
	mailer := cfg.Mailer.(*testutil.Mailer)
	body := mailer.Messages[len(mailer.Messages)-1].TextBody
	i := strings.Index(body, "token=")
	if i < 0 {
		t.Fatalf("no token in email: %q", body)
	}
	raw := body[i+len("token="):]
	if j := strings.IndexAny(raw, " \n&"); j >= 0 {
		raw = raw[:j]
	}
	if err := client.DeleteUser(ctx, signet.ConfirmDeleteUserInput{Token: raw}); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if len(store.credentials) != 0 {
		t.Fatalf("credentials remain: %+v", store.credentials)
	}
}

type passkeyAuditSink struct{ events []signet.AuditEvent }

func (s *passkeyAuditSink) Record(_ context.Context, event signet.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func TestPasskeySignCountRegressionAudit(t *testing.T) {
	store := newFakePasskeyStore()
	protocol := &fakePasskeyProtocol{}
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	sink := &passkeyAuditSink{}
	cfg.AuditSink = sink
	cfg.Passkeys = &signet.PasskeysConfig{
		RPID: "example.com", RPOrigins: []string{"https://example.com"},
		Store: store, Protocol: protocol,
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	userID, _ := passkeyUser(t, client)
	protocol.userID = userID
	ctx := context.Background()
	store.credentials[passkeyCredentialID] = &signet.WebAuthnCredential{
		ID: passkeyCredentialID, UserID: userID, SignCount: 42,
	}
	begin, err := client.BeginPasskeySignIn(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := client.FinishPasskeySignIn(ctx, signet.PasskeyFinishSignInInput{
		Token: begin.Token, Response: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	for _, event := range sink.events {
		if event.Name == "passkey_sign_count_regression" && event.Outcome == "success" {
			return
		}
	}
	t.Fatalf("no regression audit: %+v", sink.events)
}

func TestPasskeyEnrollmentRequiresVerifiedEmail(t *testing.T) {
	store := newFakePasskeyStore()
	protocol := &fakePasskeyProtocol{}
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	requireVerified := true
	cfg.RequireVerifiedEmail = &requireVerified
	cfg.Passkeys = &signet.PasskeysConfig{
		RPID: "example.com", RPOrigins: []string{"https://example.com"},
		Store: store, Protocol: protocol,
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	signUp, err := client.SignUp(ctx, signet.SignUpInput{Email: "unverified@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	protocol.userID = signUp.User.ID
	begin, err := client.BeginPasskeySignIn(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	signIn, err := client.FinishPasskeySignIn(ctx, signet.PasskeyFinishSignInInput{
		Token: begin.Token, Response: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("passkey sign in: %v", err)
	}
	_, err = client.BeginPasskeyRegistration(ctx, signet.PasskeyRegistrationInput{
		UserID: signUp.User.ID, SessionToken: signIn.SessionToken,
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("unverified enrollment error = %v", err)
	}
}

func TestPasskeyRealProtocolWiring(t *testing.T) {
	// With no injected protocol the service must construct the pinned go-webauthn
	// verifier and produce browser options for both ceremonies.
	client, _ := passkeyClient(t, newFakePasskeyStore(), nil)
	userID, token := passkeyUser(t, client)
	ctx := context.Background()
	registration, err := client.BeginPasskeyRegistration(ctx, signet.PasskeyRegistrationInput{
		UserID: userID, SessionToken: token,
	})
	if err != nil || len(registration.Options) == 0 || !strings.Contains(string(registration.Options), "challenge") {
		t.Fatalf("registration options = %s err = %v", registration.Options, err)
	}
	login, err := client.BeginPasskeySignIn(ctx)
	if err != nil || len(login.Options) == 0 || !strings.Contains(string(login.Options), "challenge") {
		t.Fatalf("login options = %s err = %v", login.Options, err)
	}
}

func TestPasskeyInvalidOriginRejectedAtStartup(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Passkeys = &signet.PasskeysConfig{
		RPID: "example.com", RPOrigins: []string{"not-an-origin"},
		Store: newFakePasskeyStore(),
	}
	if _, err := signet.New(cfg); !errors.Is(err, signet.ErrInvalidPasskeysConfig) {
		t.Fatalf("invalid origin error = %v", err)
	}
}

func TestPasskeyRegistrationBindsSessionUser(t *testing.T) {
	client, _ := passkeyClient(t, newFakePasskeyStore(), &fakePasskeyProtocol{})
	userID, token := passkeyUser(t, client)
	_, err := client.BeginPasskeyRegistration(context.Background(), signet.PasskeyRegistrationInput{
		UserID: "some-other-user", SessionToken: token,
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("mismatched session user error = %v", err)
	}
	_ = userID
}

func TestPasskeySignInRecordsLastMethod(t *testing.T) {
	protocol := &fakePasskeyProtocol{}
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.LastSignInMethod = &signet.LastSignInMethodConfig{}
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
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/passkeys/signin-finish",
		strings.NewReader(`{"token":"`+begin.Token+`","response":{}}`))
	client.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	found := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "signet_last_method" && cookie.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("last method cookie missing: %+v", rec.Result().Cookies())
	}
}

func TestPasskeyCeremonyRevokedByTokenDeletion(t *testing.T) {
	client, cfg := passkeyClient(t, newFakePasskeyStore(), &fakePasskeyProtocol{})
	userID, token := passkeyUser(t, client)
	ctx := context.Background()
	begin, err := client.BeginPasskeyRegistration(ctx, signet.PasskeyRegistrationInput{
		UserID: userID, SessionToken: token,
	})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	store := cfg.Store.(*testutil.Store)
	if err := store.DeleteTokensForUser(ctx, userID, signet.TokenPasskeyRegistration); err != nil {
		t.Fatalf("revoke tokens: %v", err)
	}
	if err := client.FinishPasskeyRegistration(ctx, signet.PasskeyFinishInput{
		Token: begin.Token, Response: json.RawMessage(`{}`), SessionToken: token,
	}); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("revoked ceremony error = %v", err)
	}
}

func TestPasskeyListingOwnerScoped(t *testing.T) {
	client, _ := passkeyClient(t, newFakePasskeyStore(), &fakePasskeyProtocol{})
	_, token := passkeyUser(t, client)
	_, err := client.ListPasskeys(context.Background(), signet.PasskeyListInput{
		UserID: "some-other-user", SessionToken: token,
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("cross-owner listing error = %v", err)
	}
}
