package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

type fakeSessionCache struct {
	mu      sync.Mutex
	values  map[string]*signet.CachedSession
	getErr  error
	putErr  error
	flushes int
}

func newFakeSessionCache() *fakeSessionCache {
	return &fakeSessionCache{values: make(map[string]*signet.CachedSession)}
}

func (c *fakeSessionCache) Get(_ context.Context, digest string) (*signet.CachedSession, error) {
	if c.getErr != nil {
		return nil, c.getErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.values[digest], nil
}

func (c *fakeSessionCache) Put(_ context.Context, digest string, value *signet.CachedSession, _ time.Duration) error {
	if c.putErr != nil {
		return c.putErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[digest] = value
	return nil
}

func (c *fakeSessionCache) Flush(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushes++
	c.values = make(map[string]*signet.CachedSession)
	return nil
}

type countingStore struct {
	*testutil.Store
	reads     int
	failUsers bool
}

func (s *countingStore) SessionByHash(ctx context.Context, digest string) (*signet.Session, error) {
	s.reads++
	return s.Store.SessionByHash(ctx, digest)
}

func (s *countingStore) UserByID(ctx context.Context, id string) (*signet.User, error) {
	if s.failUsers {
		return nil, signet.ErrNotFound
	}
	return s.Store.UserByID(ctx, id)
}

func cacheClient(t *testing.T, cache signet.SessionCache, ttl time.Duration, store *countingStore) (*signet.Client, string, *testutil.Mailer) {
	t.Helper()
	mailer := testutil.NewMailer()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = mailer
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Cookie.Name = "test_session"
	cfg.Cookie.Path = "/app"
	cfg.SessionCache = cache
	cfg.Session.CacheTTL = ttl
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	result, err := client.SignIn(context.Background(), signet.SignInInput{
		Email: "user@example.com", Password: "correct horse",
	})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	return client, result.SessionToken, mailer
}

func authenticateWithCookie(client *signet.Client, token string) int {
	handler := client.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(&http.Cookie{Name: "test_session", Value: token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr.Code
}

func TestSessionCacheHitSkipsStore(t *testing.T) {
	store := &countingStore{Store: testutil.NewStore()}
	cache := newFakeSessionCache()
	client, token, _ := cacheClient(t, cache, time.Minute, store)
	if code := authenticateWithCookie(client, token); code != http.StatusNoContent {
		t.Fatalf("first authenticate: %d", code)
	}
	reads := store.reads
	if reads == 0 {
		t.Fatal("first authenticate should populate from the Store")
	}
	if code := authenticateWithCookie(client, token); code != http.StatusNoContent {
		t.Fatalf("cached authenticate: %d", code)
	}
	if store.reads != reads {
		t.Fatalf("store reads = %d, want %d on a cache hit", store.reads, reads)
	}
}

func TestSessionCacheDisabledUsesStore(t *testing.T) {
	store := &countingStore{Store: testutil.NewStore()}
	client, token, _ := cacheClient(t, nil, 0, store)
	for i := 0; i < 2; i++ {
		if code := authenticateWithCookie(client, token); code != http.StatusNoContent {
			t.Fatalf("authenticate %d: %d", i, code)
		}
	}
	if store.reads < 2 {
		t.Fatalf("store reads = %d, want at least 2 without a cache", store.reads)
	}
}

func TestSessionCacheErrorFallsBackToStore(t *testing.T) {
	store := &countingStore{Store: testutil.NewStore()}
	cache := newFakeSessionCache()
	cache.getErr = errors.New("cache unavailable")
	client, token, _ := cacheClient(t, cache, time.Minute, store)
	if code := authenticateWithCookie(client, token); code != http.StatusNoContent {
		t.Fatalf("authenticate with broken cache: %d", code)
	}
	if store.reads == 0 {
		t.Fatal("cache failure must fall back to the Store")
	}
}

func TestSessionStoreErrorRejectsRequest(t *testing.T) {
	store := &countingStore{Store: testutil.NewStore(), failUsers: true}
	client, token, _ := cacheClient(t, newFakeSessionCache(), time.Minute, store)
	if code := authenticateWithCookie(client, token); code != http.StatusUnauthorized {
		t.Fatalf("authenticate with broken Store = %d, want 401", code)
	}
}

func cachedUserID(t *testing.T, store *countingStore) string {
	t.Helper()
	user, err := store.UserByEmail(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("UserByEmail: %v", err)
	}
	return user.ID
}

func assertCacheFlushed(t *testing.T, cache *fakeSessionCache, token string, client *signet.Client) {
	t.Helper()
	if cache.flushes == 0 {
		t.Fatal("revocation did not flush the Session cache")
	}
	if code := authenticateWithCookie(client, token); code != http.StatusUnauthorized {
		t.Fatalf("cached Session still authenticates after revocation: %d", code)
	}
}

func TestSessionCacheFlushOnRevokeSession(t *testing.T) {
	store := &countingStore{Store: testutil.NewStore()}
	cache := newFakeSessionCache()
	client, token, _ := cacheClient(t, cache, time.Minute, store)
	authenticateWithCookie(client, token)
	sessions, err := client.ListSessions(context.Background(), signet.ListSessionsInput{UserID: cachedUserID(t, store)})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if err := client.RevokeSession(context.Background(), signet.RevokeSessionInput{SessionID: sessions.Sessions[0].ID}); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	assertCacheFlushed(t, cache, token, client)
}

func TestSessionCacheFlushOnRevokeAll(t *testing.T) {
	store := &countingStore{Store: testutil.NewStore()}
	cache := newFakeSessionCache()
	client, token, _ := cacheClient(t, cache, time.Minute, store)
	authenticateWithCookie(client, token)
	if err := client.RevokeAllSessions(context.Background(), signet.RevokeAllSessionsInput{UserID: cachedUserID(t, store)}); err != nil {
		t.Fatalf("RevokeAllSessions: %v", err)
	}
	assertCacheFlushed(t, cache, token, client)
}

func TestSessionCacheFlushOnSignOut(t *testing.T) {
	store := &countingStore{Store: testutil.NewStore()}
	cache := newFakeSessionCache()
	client, token, _ := cacheClient(t, cache, time.Minute, store)
	authenticateWithCookie(client, token)
	if err := client.SignOut(context.Background(), signet.SignOutInput{SessionToken: token}); err != nil {
		t.Fatalf("SignOut: %v", err)
	}
	assertCacheFlushed(t, cache, token, client)
}

func tokenFromMail(t *testing.T, mailer *testutil.Mailer) string {
	t.Helper()
	if len(mailer.Messages) == 0 {
		t.Fatal("no email captured")
	}
	body := mailer.Messages[len(mailer.Messages)-1].TextBody
	i := strings.Index(body, "token=")
	if i < 0 {
		t.Fatalf("no token in email: %q", body)
	}
	raw := body[i+len("token="):]
	if j := strings.IndexAny(raw, " \n&"); j >= 0 {
		raw = raw[:j]
	}
	return raw
}

func TestSessionCacheFlushOnPasswordReset(t *testing.T) {
	store := &countingStore{Store: testutil.NewStore()}
	cache := newFakeSessionCache()
	client, token, mailer := cacheClient(t, cache, time.Minute, store)
	authenticateWithCookie(client, token)
	ctx := context.Background()
	if err := client.SendPasswordReset(ctx, signet.SendPasswordResetInput{Email: "user@example.com"}); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}
	if err := client.ResetPassword(ctx, signet.ResetPasswordInput{
		Token: tokenFromMail(t, mailer), NewPassword: "new strong password",
	}); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	assertCacheFlushed(t, cache, token, client)
}

func TestSessionCacheFlushOnRefreshReuse(t *testing.T) {
	store := &countingStore{Store: testutil.NewStore()}
	cache := newFakeSessionCache()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.Cookie.Name = "test_session"
	cfg.Cookie.Path = "/app"
	cfg.SessionCache = cache
	cfg.Session.CacheTTL = time.Minute
	cfg.JWT = &signet.JWTConfig{Algorithm: "HS256", Key: []byte("0123456789abcdef0123456789abcdef")}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := client.SignUp(ctx, signet.SignUpInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	pair, err := client.ExchangeToken(ctx, signet.TokenInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if code := authenticateWithCookie(client, ""); code != http.StatusUnauthorized {
		t.Fatal("no session token should not authenticate")
	}
	if _, err := client.ExchangeToken(ctx, signet.TokenInput{RefreshToken: pair.RefreshToken}); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if _, err := client.ExchangeToken(ctx, signet.TokenInput{RefreshToken: pair.RefreshToken}); !errors.Is(err, signet.ErrRefreshReuse) {
		t.Fatalf("replayed refresh error = %v", err)
	}
	if cache.flushes == 0 {
		t.Fatal("refresh-theft containment did not flush the Session cache")
	}
}
