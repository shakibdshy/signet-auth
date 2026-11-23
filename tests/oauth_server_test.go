package tests

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

type fakeOAuthClientStore struct {
	clients map[string]*signet.OAuthClient
}

func newFakeOAuthClientStore() *fakeOAuthClientStore {
	return &fakeOAuthClientStore{clients: make(map[string]*signet.OAuthClient)}
}

func (s *fakeOAuthClientStore) Get(_ context.Context, id string) (*signet.OAuthClient, error) {
	c, ok := s.clients[id]
	if !ok {
		return nil, signet.ErrNotFound
	}
	return c, nil
}
func (s *fakeOAuthClientStore) Authenticate(ctx context.Context, id, secret string) (*signet.OAuthClient, error) {
	c, err := s.Get(ctx, id)
	if err != nil || c.Secret != secret {
		return nil, signet.ErrNotFound
	}
	return c, nil
}
func (s *fakeOAuthClientStore) IsTrusted(ctx context.Context, id string) (bool, error) {
	c, err := s.Get(ctx, id)
	if err != nil {
		return false, err
	}
	return c.Trusted, nil
}
func (s *fakeOAuthClientStore) AllowedRedirects(ctx context.Context, id string) ([]string, error) {
	c, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return c.RedirectURIs, nil
}

type fakeDeviceStore struct {
	devices map[string]*signet.DeviceAuthorization
}

func newFakeDeviceStore() *fakeDeviceStore {
	return &fakeDeviceStore{devices: make(map[string]*signet.DeviceAuthorization)}
}

func (s *fakeDeviceStore) Create(_ context.Context, d *signet.DeviceAuthorization) error {
	clone := *d
	s.devices[d.DeviceCode] = &clone
	return nil
}
func (s *fakeDeviceStore) ByUserCode(_ context.Context, code string) (*signet.DeviceAuthorization, error) {
	for _, d := range s.devices {
		if d.UserCode == code {
			clone := *d
			return &clone, nil
		}
	}
	return nil, signet.ErrNotFound
}
func (s *fakeDeviceStore) ByDeviceCode(_ context.Context, code string) (*signet.DeviceAuthorization, error) {
	d, ok := s.devices[code]
	if !ok {
		return nil, signet.ErrNotFound
	}
	clone := *d
	return &clone, nil
}
func (s *fakeDeviceStore) IncrementPoll(_ context.Context, code string) error {
	if d, ok := s.devices[code]; ok {
		d.PollCount++
	}
	return nil
}
func (s *fakeDeviceStore) Consume(_ context.Context, code string) error {
	delete(s.devices, code)
	return nil
}
func (s *fakeDeviceStore) Approve(_ context.Context, userCode, userID string) error {
	for _, d := range s.devices {
		if d.UserCode == userCode {
			d.Approved = true
			d.UserID = userID
			return nil
		}
	}
	return signet.ErrNotFound
}

type oauthServerAuditSink struct{ events []signet.AuditEvent }

func (s *oauthServerAuditSink) Record(_ context.Context, event signet.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func oauthServerClient(t *testing.T, clients *fakeOAuthClientStore, devices *fakeDeviceStore, consent func(context.Context, string, string, []string) bool, sink signet.AuditSink) (*signet.Client, string) {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AppURL = "https://app.example.com"
	cfg.JWT = &signet.JWTConfig{Algorithm: "HS256", Key: []byte("authorization-server-test-key-1234")}
	cfg.AuthorizationServer = &signet.AuthorizationServerConfig{
		Clients: clients, Devices: devices, Consent: consent,
		Audiences: []string{"api.example.com"}, DeviceTTL: time.Minute,
	}
	cfg.AuditSink = sink
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "owner@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	session, err := client.SignIn(ctx, signet.SignInInput{Email: "owner@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	return client, session.SessionToken
}

func challenge() string {
	sum := sha256.Sum256([]byte("verifier-1234567890"))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestOAuthServerCodeExchange(t *testing.T) {
	clients := newFakeOAuthClientStore()
	clients.clients["app"] = &signet.OAuthClient{ID: "app", Secret: "secret", RedirectURIs: []string{"https://app.example.com/cb"}, Trusted: true}
	client, session := oauthServerClient(t, clients, newFakeDeviceStore(), nil, nil)
	ctx := context.Background()
	auth, err := client.OAuthAuthorize(ctx, signet.OAuthAuthorizeInput{
		ClientID: "app", RedirectURI: "https://app.example.com/cb", ResponseType: "code",
		Scope: "openid email", State: "xyz", CodeChallenge: challenge(), Audience: "api.example.com",
		SessionToken: session,
	})
	if err != nil || auth.Code == "" {
		t.Fatalf("authorize = %+v err = %v", auth, err)
	}
	tokens, err := client.OAuthExchange(ctx, signet.OAuthTokenInput{
		GrantType: "authorization_code", Code: auth.Code, CodeVerifier: "verifier-1234567890",
		ClientID: "app", ClientSecret: "secret", RedirectURI: "https://app.example.com/cb",
	})
	if err != nil || tokens.AccessToken == "" || tokens.Scope != "openid email" {
		t.Fatalf("tokens = %+v err = %v", tokens, err)
	}
	if _, err := client.OAuthExchange(ctx, signet.OAuthTokenInput{
		GrantType: "authorization_code", Code: auth.Code, CodeVerifier: "verifier-1234567890", ClientID: "app", RedirectURI: "https://app.example.com/cb",
	}); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("code replay error = %v", err)
	}
}

func TestOAuthServerPKCEAndBinding(t *testing.T) {
	clients := newFakeOAuthClientStore()
	clients.clients["app"] = &signet.OAuthClient{ID: "app", RedirectURIs: []string{"https://app.example.com/cb"}, Trusted: true}
	client, session := oauthServerClient(t, clients, newFakeDeviceStore(), nil, nil)
	ctx := context.Background()
	auth, err := client.OAuthAuthorize(ctx, signet.OAuthAuthorizeInput{
		ClientID: "app", RedirectURI: "https://app.example.com/cb", ResponseType: "code",
		Scope: "openid", CodeChallenge: challenge(), SessionToken: session,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if _, err := client.OAuthExchange(ctx, signet.OAuthTokenInput{
		GrantType: "authorization_code", Code: auth.Code, CodeVerifier: "wrong", ClientID: "app", RedirectURI: "https://app.example.com/cb",
	}); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("wrong verifier error = %v", err)
	}
	_, err = client.OAuthAuthorize(ctx, signet.OAuthAuthorizeInput{
		ClientID: "app", RedirectURI: "https://evil.example.com", ResponseType: "code",
		Scope: "openid", CodeChallenge: challenge(), SessionToken: session,
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("bad redirect error = %v", err)
	}
}

func TestOAuthServerRefreshRotation(t *testing.T) {
	clients := newFakeOAuthClientStore()
	clients.clients["app"] = &signet.OAuthClient{ID: "app", RedirectURIs: []string{"https://app.example.com/cb"}, Trusted: true}
	client, session := oauthServerClient(t, clients, newFakeDeviceStore(), nil, nil)
	ctx := context.Background()
	auth, err := client.OAuthAuthorize(ctx, signet.OAuthAuthorizeInput{
		ClientID: "app", RedirectURI: "https://app.example.com/cb", ResponseType: "code",
		Scope: "openid email", CodeChallenge: challenge(), Audience: "api.example.com", SessionToken: session,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	tokens, err := client.OAuthExchange(ctx, signet.OAuthTokenInput{
		GrantType: "authorization_code", Code: auth.Code, CodeVerifier: "verifier-1234567890", ClientID: "app", RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	refreshed, err := client.OAuthRefresh(ctx, signet.OAuthTokenInput{
		GrantType: "refresh_token", RefreshToken: tokens.RefreshToken,
	})
	if err != nil || refreshed.AccessToken == "" || refreshed.Scope != "openid email" {
		t.Fatalf("refresh = %+v err = %v", refreshed, err)
	}
	if _, err := client.OAuthRefresh(ctx, signet.OAuthTokenInput{
		GrantType: "refresh_token", RefreshToken: tokens.RefreshToken,
	}); !errors.Is(err, signet.ErrRefreshReuse) {
		t.Fatalf("reuse error = %v", err)
	}
}

func TestOAuthServerConsentAndScopes(t *testing.T) {
	clients := newFakeOAuthClientStore()
	clients.clients["app"] = &signet.OAuthClient{ID: "app", RedirectURIs: []string{"https://app.example.com/cb"}}
	approved := false
	sink := &oauthServerAuditSink{}
	client, session := oauthServerClient(t, clients, newFakeDeviceStore(), func(_ context.Context, _, _ string, _ []string) bool {
		return approved
	}, sink)
	ctx := context.Background()
	in := signet.OAuthAuthorizeInput{
		ClientID: "app", RedirectURI: "https://app.example.com/cb", ResponseType: "code",
		Scope: "openid", CodeChallenge: challenge(), SessionToken: session,
	}
	if _, err := client.OAuthAuthorize(ctx, in); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("denied consent error = %v", err)
	}
	approved = true
	if _, err := client.OAuthAuthorize(ctx, in); err != nil {
		t.Fatalf("approved consent: %v", err)
	}
	in.Scope = "openid admin"
	in.Audience = "evil.example.com"
	if _, err := client.OAuthAuthorize(ctx, in); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("bad scope/audience error = %v", err)
	}
	found := false
	for _, event := range sink.events {
		if event.Name == "oauth_consent_denied" && event.Outcome == "denied" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no denial audit: %+v", sink.events)
	}
}

func TestOAuthServerDeviceFlow(t *testing.T) {
	clients := newFakeOAuthClientStore()
	clients.clients["app"] = &signet.OAuthClient{ID: "app", Trusted: true}
	devices := newFakeDeviceStore()
	client, session := oauthServerClient(t, clients, devices, nil, nil)
	ctx := context.Background()
	begin, err := client.BeginDeviceAuthorization(ctx, signet.DeviceAuthorizeInput{
		ClientID: "app", Scope: "openid", Audience: "api.example.com",
	})
	if err != nil || begin.UserCode == "" || !strings.Contains(begin.VerificationURL, "/oauth/device/approve") {
		t.Fatalf("begin = %+v err = %v", begin, err)
	}
	if _, err := client.ExchangeDeviceAuthorization(ctx, begin.DeviceCode); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("pre-approval error = %v", err)
	}
	if err := client.ApproveDeviceAuthorization(ctx, signet.DeviceApproveInput{UserCode: strings.ToLower(begin.UserCode), SessionToken: session}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	tokens, err := client.ExchangeDeviceAuthorization(ctx, begin.DeviceCode)
	if err != nil || tokens.AccessToken == "" {
		t.Fatalf("device tokens = %+v err = %v", tokens, err)
	}
	_ = session
}

func TestOAuthServerDisabled(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.OAuthExchange(context.Background(), signet.OAuthTokenInput{}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("disabled error = %v", err)
	}
}

func TestOAuthServerHTTPEndpoints(t *testing.T) {
	clients := newFakeOAuthClientStore()
	clients.clients["app"] = &signet.OAuthClient{ID: "app", RedirectURIs: []string{"https://app.example.com/cb"}, Trusted: true}
	client, session := oauthServerClient(t, clients, newFakeDeviceStore(), nil, nil)
	ctx := context.Background()
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	authorizeReq := httptest.NewRequest(http.MethodPost, "/oauth/authorize",
		strings.NewReader("client_id=app&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=openid&code_challenge="+challenge()))
	authorizeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authorizeReq.AddCookie(&http.Cookie{Name: "__Host-signet_session", Value: session, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	authorizeReq.AddCookie(csrfCookie)
	authorizeReq.Header.Set("X-CSRF-Token", csrfToken)
	rr := httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, authorizeReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("authorize status = %d body = %s", rr.Code, rr.Body.String())
	}
	var result struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil || result.Code == "" {
		t.Fatalf("decode = %v body = %s", err, rr.Body.String())
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code="+result.Code+"&code_verifier=verifier-1234567890&client_id=app&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, tokenReq)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "access_token") {
		t.Fatalf("token status = %d body = %s", rr.Code, rr.Body.String())
	}
	_ = ctx
}

func TestOAuthServerClientSecretAndRedirectBinding(t *testing.T) {
	clients := newFakeOAuthClientStore()
	clients.clients["app"] = &signet.OAuthClient{
		ID: "app", Secret: "right-secret", RedirectURIs: []string{"https://app.example.com/cb"}, Trusted: true,
	}
	client, session := oauthServerClient(t, clients, newFakeDeviceStore(), nil, nil)
	ctx := context.Background()
	verifier := "verifier-1234567890"
	auth, err := client.OAuthAuthorize(ctx, signet.OAuthAuthorizeInput{
		ClientID: "app", RedirectURI: "https://app.example.com/cb", ResponseType: "code",
		Scope: "openid", CodeChallenge: challenge(), Audience: "api.example.com", SessionToken: session,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if _, err := client.OAuthExchange(ctx, signet.OAuthTokenInput{
		GrantType: "authorization_code", Code: auth.Code, CodeVerifier: verifier,
		ClientID: "app", ClientSecret: "wrong-secret", RedirectURI: "https://app.example.com/cb",
	}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("wrong secret error = %v", err)
	}
	second, err := client.OAuthAuthorize(ctx, signet.OAuthAuthorizeInput{
		ClientID: "app", RedirectURI: "https://app.example.com/cb", ResponseType: "code",
		Scope: "openid", CodeChallenge: challenge(), Audience: "api.example.com", SessionToken: session,
	})
	if err != nil {
		t.Fatalf("second authorize: %v", err)
	}
	if _, err := client.OAuthExchange(ctx, signet.OAuthTokenInput{
		GrantType: "authorization_code", Code: second.Code, CodeVerifier: verifier,
		ClientID: "app", ClientSecret: "right-secret", RedirectURI: "https://evil.example.com",
	}); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("wrong redirect error = %v", err)
	}
}

func TestOAuthServerSlowDownAndDeviceConsume(t *testing.T) {
	clients := newFakeOAuthClientStore()
	clients.clients["app"] = &signet.OAuthClient{ID: "app", Trusted: true}
	devices := newFakeDeviceStore()
	client, session := oauthServerClient(t, clients, devices, nil, nil)
	ctx := context.Background()
	begin, err := client.BeginDeviceAuthorization(ctx, signet.DeviceAuthorizeInput{
		ClientID: "app", Scope: "openid", Audience: "api.example.com",
	})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := client.ApproveDeviceAuthorization(ctx, signet.DeviceApproveInput{UserCode: begin.UserCode, SessionToken: session}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := client.ExchangeDeviceAuthorization(ctx, begin.DeviceCode); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if _, err := client.ExchangeDeviceAuthorization(ctx, begin.DeviceCode); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("replayed device code error = %v", err)
	}
}

func TestOAuthServerUntrustedWithoutConsentDenied(t *testing.T) {
	clients := newFakeOAuthClientStore()
	clients.clients["app"] = &signet.OAuthClient{ID: "app", RedirectURIs: []string{"https://app.example.com/cb"}}
	client, session := oauthServerClient(t, clients, newFakeDeviceStore(), nil, nil)
	_, err := client.OAuthAuthorize(context.Background(), signet.OAuthAuthorizeInput{
		ClientID: "app", RedirectURI: "https://app.example.com/cb", ResponseType: "code",
		Scope: "openid", CodeChallenge: challenge(), SessionToken: session,
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("missing consent error = %v", err)
	}
}

func TestOAuthServerSlowDownError(t *testing.T) {
	clients := newFakeOAuthClientStore()
	clients.clients["app"] = &signet.OAuthClient{ID: "app", Trusted: true}
	devices := newFakeDeviceStore()
	client, _ := oauthServerClient(t, clients, devices, nil, nil)
	ctx := context.Background()
	begin, err := client.BeginDeviceAuthorization(ctx, signet.DeviceAuthorizeInput{ClientID: "app", Scope: "openid"})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := client.ExchangeDeviceAuthorization(ctx, begin.DeviceCode); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("first poll error = %v", err)
	}
	if _, err := client.ExchangeDeviceAuthorization(ctx, begin.DeviceCode); !errors.Is(err, signet.ErrOAuthSlowDown) {
		t.Fatalf("second poll error = %v", err)
	}
}

func TestOAuthServerConfigValidation(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.AuthorizationServer = &signet.AuthorizationServerConfig{}
	if _, err := signet.New(cfg); !errors.Is(err, signet.ErrInvalidAuthorizationServerConfig) {
		t.Fatalf("validation error = %v", err)
	}
}
