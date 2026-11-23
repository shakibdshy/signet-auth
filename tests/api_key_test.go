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

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

type apiKeyRecord struct {
	signet.APIKey
	remaining int
}

type fakeAPIKeyStore struct {
	keys         map[string]*apiKeyRecord
	ownerKeys    map[string][]string
	consumeCalls int
}

func newFakeAPIKeyStore() *fakeAPIKeyStore {
	return &fakeAPIKeyStore{keys: make(map[string]*apiKeyRecord), ownerKeys: make(map[string][]string)}
}

func (s *fakeAPIKeyStore) Create(_ context.Context, key *signet.APIKey) error {
	s.keys[key.ID] = &apiKeyRecord{APIKey: *key, remaining: key.Remaining}
	s.ownerKeys[key.OwnerUserID] = append(s.ownerKeys[key.OwnerUserID], key.ID)
	return nil
}

func (s *fakeAPIKeyStore) ConsumeAPIKey(_ context.Context, digest string) (*signet.APIKey, error) {
	s.consumeCalls++
	for _, record := range s.keys {
		if record.Hash == digest && record.remaining > 0 &&
			(record.ExpiresAt.IsZero() || time.Now().Before(record.ExpiresAt)) {
			record.remaining--
			clone := record.APIKey
			clone.Remaining = record.remaining
			return &clone, nil
		}
	}
	return nil, signet.ErrNotFound
}

func (s *fakeAPIKeyStore) List(_ context.Context, owner string) ([]*signet.APIKey, error) {
	ids := s.ownerKeys[owner]
	out := make([]*signet.APIKey, 0, len(ids))
	for _, id := range ids {
		clone := s.keys[id].APIKey
		out = append(out, &clone)
	}
	return out, nil
}

func (s *fakeAPIKeyStore) Revoke(_ context.Context, id string) error {
	delete(s.keys, id)
	return nil
}

func apiKeyClient(t *testing.T, store *fakeAPIKeyStore, authorizer signet.Authorizer) (*signet.Client, string) {
	t.Helper()
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.APIKeyStore = store
	cfg.Authorizer = authorizer
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	return client, result.SessionToken
}

func TestAPIKeyCreateVerifyRevoke(t *testing.T) {
	store := newFakeAPIKeyStore()
	client, session := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true, "api-keys:revoke": true}})
	ctx := context.Background()
	created, err := client.CreateAPIKey(ctx, signet.CreateAPIKeyInput{
		OwnerUserID: "user-1", SessionToken: session, Name: "ci", Roles: []string{"ci"}, Remaining: 2,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if created.Raw == "" || len(created.Raw) < 20 {
		t.Fatalf("raw key = %q", created.Raw)
	}
	principal, err := client.VerifyAPIKey(ctx, created.Raw)
	if err != nil {
		t.Fatalf("VerifyAPIKey: %v", err)
	}
	if principal.OwnerUserID != "user-1" || principal.Roles[0] != "ci" {
		t.Fatalf("principal = %+v", principal)
	}
	if _, err := client.VerifyAPIKey(ctx, created.Raw); err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if _, err := client.VerifyAPIKey(ctx, created.Raw); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("exhausted key error = %v", err)
	}
	list, err := client.ListAPIKeys(ctx, signet.ListAPIKeysInput{OwnerUserID: "user-1", SessionToken: session})
	if err != nil || len(list.Keys) != 1 {
		t.Fatalf("list = %+v, err = %v", list, err)
	}
	if err := client.RevokeAPIKey(ctx, signet.RevokeAPIKeyInput{OwnerUserID: "user-1", SessionToken: session, ID: created.Key.ID}); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if _, err := client.VerifyAPIKey(ctx, created.Raw); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("revoked key error = %v", err)
	}
}

func TestAPIKeyRequiresPermission(t *testing.T) {
	store := newFakeAPIKeyStore()
	client, session := apiKeyClient(t, store, &fakeAuthorizer{})
	_, err := client.CreateAPIKey(context.Background(), signet.CreateAPIKeyInput{OwnerUserID: "user-1", SessionToken: session})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("error = %v, want ErrForbidden", err)
	}
}

func TestAPIKeyOwnerScoping(t *testing.T) {
	store := newFakeAPIKeyStore()
	client, session := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true, "api-keys:revoke": true}})
	ctx := context.Background()
	created, err := client.CreateAPIKey(ctx, signet.CreateAPIKeyInput{OwnerUserID: "user-1", SessionToken: session, Remaining: 5})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	list, _ := client.ListAPIKeys(ctx, signet.ListAPIKeysInput{OwnerUserID: "other", SessionToken: session})
	if len(list.Keys) != 0 {
		t.Fatalf("other owner sees %d keys", len(list.Keys))
	}
	if err := client.RevokeAPIKey(ctx, signet.RevokeAPIKeyInput{OwnerUserID: "other", SessionToken: session, ID: created.Key.ID}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("cross-owner revoke error = %v", err)
	}
}

func TestAPIKeyRawNotStored(t *testing.T) {
	store := newFakeAPIKeyStore()
	client, session := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true}})
	created, err := client.CreateAPIKey(context.Background(), signet.CreateAPIKeyInput{OwnerUserID: "user-1", SessionToken: session})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	for _, record := range store.keys {
		if strings.Contains(record.Hash, created.Raw) {
			t.Fatal("raw API key stored")
		}
	}
}

func TestAPIKeyHTTPEndpoints(t *testing.T) {
	store := newFakeAPIKeyStore()
	authorizer := &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true, "api-keys:revoke": true}}
	client, session := apiKeyClient(t, store, authorizer)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api-keys", strings.NewReader(`{"name":"ci"}`))
	req.AddCookie(&http.Cookie{Name: "__Host-signet_session", Value: session, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", csrfToken)
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated || !strings.Contains(rr.Body.String(), "raw") {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestAPIKeyMiddleware(t *testing.T) {
	store := newFakeAPIKeyStore()
	authorizer := &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true}}
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.APIKeyStore = store
	cfg.Authorizer = authorizer
	cfg.APIKeyProtectedEndpoints = []string{"csrf-token"}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	created, err := client.CreateAPIKey(ctx, signet.CreateAPIKeyInput{OwnerUserID: "user-1", SessionToken: signIn.SessionToken, Remaining: 5})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	// Without a key the protected endpoint rejects.
	rr := httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/csrf-token", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-key status = %d", rr.Code)
	}
	// With a key it succeeds.
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/csrf-token", nil)
	req.Header.Set("X-API-Key", created.Raw)
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("with-key status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestAPIKeyExpiredAndMissing(t *testing.T) {
	store := newFakeAPIKeyStore()
	client, session := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true}})
	ctx := context.Background()
	if _, err := client.VerifyAPIKey(ctx, "does-not-exist"); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("missing key error = %v", err)
	}
	expired, err := client.CreateAPIKey(ctx, signet.CreateAPIKeyInput{
		OwnerUserID: "user-1", SessionToken: session, Remaining: 5,
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if _, err := client.VerifyAPIKey(ctx, expired.Raw); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("expired key error = %v", err)
	}
}

func TestAPIKeyRequiresFreshSession(t *testing.T) {
	store := newFakeAPIKeyStore()
	client, _ := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true}})
	ctx := context.Background()
	_, err := client.CreateAPIKey(ctx, signet.CreateAPIKeyInput{OwnerUserID: "user-1", SessionToken: "stale-token"})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("stale session error = %v", err)
	}
}

func TestAPIKeySuccessAudit(t *testing.T) {
	store := newFakeAPIKeyStore()
	sink := &recordingAuditSink{}
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.APIKeyStore = store
	cfg.Authorizer = &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true, "api-keys:revoke": true}}
	cfg.AuditSink = sink
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "audit@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn, err := client.SignIn(ctx, signet.SignInInput{Email: "audit@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	created, err := client.CreateAPIKey(ctx, signet.CreateAPIKeyInput{OwnerUserID: "user-1", SessionToken: signIn.SessionToken})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if err := client.RevokeAPIKey(ctx, signet.RevokeAPIKeyInput{OwnerUserID: "user-1", SessionToken: signIn.SessionToken, ID: created.Key.ID}); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	names := make(map[string]bool)
	for _, event := range sink.events {
		names[event.Name] = true
		if event.Outcome != "success" {
			t.Fatalf("unexpected outcome %q for %s", event.Outcome, event.Name)
		}
	}
	if !names["api_key_created"] || !names["api_key_revoked"] {
		t.Fatalf("audit events = %+v", sink.events)
	}
}

func TestAPIKeyProtectedRouteIgnoresSession(t *testing.T) {
	store := newFakeAPIKeyStore()
	authorizer := &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true}}
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.APIKeyStore = store
	cfg.Authorizer = authorizer
	cfg.APIKeyProtectedEndpoints = []string{"csrf-token"}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "ignored@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signIn, err := client.SignIn(ctx, signet.SignInInput{Email: "ignored@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	created, err := client.CreateAPIKey(ctx, signet.CreateAPIKeyInput{OwnerUserID: "user-1", SessionToken: signIn.SessionToken, Remaining: 5})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	// A valid session alone must not grant access to a protected route.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/csrf-token", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-signet_session", Value: signIn.SessionToken, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("session-only status = %d", rr.Code)
	}
	// The key must be accepted.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/csrf-token", nil)
	req.Header.Set("X-API-Key", created.Raw)
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("key status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestAPIKeyRevokeHTTPEndpoint(t *testing.T) {
	store := newFakeAPIKeyStore()
	client, session := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true, "api-keys:revoke": true}})
	ctx := context.Background()
	// Create through HTTP so the key owner matches the authenticated User.
	cookies := &http.Cookie{Name: "__Host-signet_session", Value: session, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	createReq := httptest.NewRequest(http.MethodPost, "/api-keys", strings.NewReader(`{"name":"ci","remaining":5}`))
	createReq.AddCookie(cookies)
	createReq.AddCookie(csrfCookie)
	createReq.Header.Set("X-CSRF-Token", csrfToken)
	createRec := httptest.NewRecorder()
	client.Handler().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createRec.Code, createRec.Body.String())
	}
	var created struct {
		Raw string `json:"raw"`
		Key struct {
			ID string `json:"id"`
		} `json:"key"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/revoke-api-key",
		strings.NewReader(`{"id":"`+created.Key.ID+`"}`))
	req.AddCookie(cookies)
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", csrfToken)
	client.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	if _, err := client.VerifyAPIKey(ctx, created.Raw); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("revoked key error = %v", err)
	}
}

func TestAPIKeyVerifyUsesSingleAtomicStoreCall(t *testing.T) {
	store := newFakeAPIKeyStore()
	client, session := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true}})
	ctx := context.Background()
	created, err := client.CreateAPIKey(ctx, signet.CreateAPIKeyInput{
		OwnerUserID: "user-1", SessionToken: session, Remaining: 3,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	before := store.consumeCalls
	if _, err := client.VerifyAPIKey(ctx, created.Raw); err != nil {
		t.Fatalf("VerifyAPIKey: %v", err)
	}
	if store.consumeCalls != before+1 {
		t.Fatalf("consume calls = %d, want %d", store.consumeCalls, before+1)
	}
}

func TestAPIKeyPrefixIsNotRaw(t *testing.T) {
	store := newFakeAPIKeyStore()
	client, session := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true}})
	created, err := client.CreateAPIKey(context.Background(), signet.CreateAPIKeyInput{
		OwnerUserID: "user-1", SessionToken: session,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	for _, record := range store.keys {
		if strings.Contains(record.Prefix, created.Raw) || strings.Contains(created.Raw, record.Prefix) {
			t.Fatalf("prefix %q derived from raw key", record.Prefix)
		}
	}
}

func TestAPIKeyListingRequiresSession(t *testing.T) {
	store := newFakeAPIKeyStore()
	client, _ := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:revoke": true}})
	_, err := client.ListAPIKeys(context.Background(), signet.ListAPIKeysInput{
		OwnerUserID: "user-1", SessionToken: "stale-token",
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("listing error = %v", err)
	}
}

func TestAPIKeyListAndVerifyHTTPEndpoints(t *testing.T) {
	store := newFakeAPIKeyStore()
	client, session := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true, "api-keys:revoke": true}})
	cookies := &http.Cookie{Name: "__Host-signet_session", Value: session, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	csrfToken, csrfCookie := issueCSRFToken(t, client)
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/api-keys", strings.NewReader(`{"name":"ci","remaining":5}`))
	createReq.AddCookie(cookies)
	createReq.AddCookie(csrfCookie)
	createReq.Header.Set("X-CSRF-Token", csrfToken)
	client.Handler().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createRec.Code, createRec.Body.String())
	}
	var created struct {
		Raw string `json:"raw"`
		Key struct {
			ID string `json:"id"`
		} `json:"key"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// GET /api-keys lists the signed-in User's keys.
	listRec := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/api-keys", nil)
	listReq.AddCookie(cookies)
	client.Handler().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK || !strings.Contains(listRec.Body.String(), created.Key.ID) {
		t.Fatalf("list status = %d body = %s", listRec.Code, listRec.Body.String())
	}

	// POST /verify-api-key returns a Principal for a valid key.
	verifyRec := httptest.NewRecorder()
	verifyReq := httptest.NewRequest(http.MethodPost, "/verify-api-key", nil)
	verifyReq.Header.Set("X-API-Key", created.Raw)
	client.Handler().ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK || !strings.Contains(verifyRec.Body.String(), "owner_user_id") {
		t.Fatalf("verify status = %d body = %s", verifyRec.Code, verifyRec.Body.String())
	}
}

func TestAPIKeyListingRequiresGrant(t *testing.T) {
	store := newFakeAPIKeyStore()
	client, session := apiKeyClient(t, store, &fakeAuthorizer{})
	_, err := client.ListAPIKeys(context.Background(), signet.ListAPIKeysInput{
		OwnerUserID: "user-1", SessionToken: session,
	})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("listing error = %v", err)
	}
}
