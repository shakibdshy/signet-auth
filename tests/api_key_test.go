package tests

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

type apiKeyRecord struct {
	signet.APIKey
	remaining int
}

type fakeAPIKeyStore struct {
	keys      map[string]*apiKeyRecord
	ownerKeys map[string][]string
}

func newFakeAPIKeyStore() *fakeAPIKeyStore {
	return &fakeAPIKeyStore{keys: make(map[string]*apiKeyRecord), ownerKeys: make(map[string][]string)}
}

func (s *fakeAPIKeyStore) Create(_ context.Context, key *signet.APIKey) error {
	s.keys[key.ID] = &apiKeyRecord{APIKey: *key, remaining: key.Remaining}
	s.ownerKeys[key.OwnerUserID] = append(s.ownerKeys[key.OwnerUserID], key.ID)
	return nil
}

func (s *fakeAPIKeyStore) Consume(_ context.Context, raw string) (*signet.APIKey, error) {
	digest := testutil.DigestForTest(raw)
	for _, record := range s.keys {
		if record.Hash == digest && record.remaining > 0 {
			record.remaining--
			copy := record.APIKey
			copy.Remaining = record.remaining
			return &copy, nil
		}
	}
	return nil, signet.ErrNotFound
}

func (s *fakeAPIKeyStore) List(_ context.Context, owner string) ([]*signet.APIKey, error) {
	ids := s.ownerKeys[owner]
	out := make([]*signet.APIKey, 0, len(ids))
	for _, id := range ids {
		copy := s.keys[id].APIKey
		out = append(out, &copy)
	}
	return out, nil
}

func (s *fakeAPIKeyStore) Revoke(_ context.Context, id string) error {
	delete(s.keys, id)
	return nil
}

func apiKeyClient(t *testing.T, store *fakeAPIKeyStore, authorizer signet.Authorizer) *signet.Client {
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
	return client
}

func TestAPIKeyCreateVerifyRevoke(t *testing.T) {
	store := newFakeAPIKeyStore()
	client := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true, "api-keys:revoke": true}})
	ctx := context.Background()
	created, err := client.CreateAPIKey(ctx, signet.CreateAPIKeyInput{
		OwnerUserID: "user-1", Name: "ci", Roles: []string{"ci"}, Remaining: 2,
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
	list, err := client.ListAPIKeys(ctx, signet.ListAPIKeysInput{OwnerUserID: "user-1"})
	if err != nil || len(list.Keys) != 1 {
		t.Fatalf("list = %+v, err = %v", list, err)
	}
	if err := client.RevokeAPIKey(ctx, signet.RevokeAPIKeyInput{OwnerUserID: "user-1", ID: created.Key.ID}); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if _, err := client.VerifyAPIKey(ctx, created.Raw); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("revoked key error = %v", err)
	}
}

func TestAPIKeyRequiresPermission(t *testing.T) {
	store := newFakeAPIKeyStore()
	client := apiKeyClient(t, store, &fakeAuthorizer{})
	_, err := client.CreateAPIKey(context.Background(), signet.CreateAPIKeyInput{OwnerUserID: "user-1"})
	if !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("error = %v, want ErrForbidden", err)
	}
}

func TestAPIKeyOwnerScoping(t *testing.T) {
	store := newFakeAPIKeyStore()
	client := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true, "api-keys:revoke": true}})
	ctx := context.Background()
	created, err := client.CreateAPIKey(ctx, signet.CreateAPIKeyInput{OwnerUserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	list, _ := client.ListAPIKeys(ctx, signet.ListAPIKeysInput{OwnerUserID: "other"})
	if len(list.Keys) != 0 {
		t.Fatalf("other owner sees %d keys", len(list.Keys))
	}
	if err := client.RevokeAPIKey(ctx, signet.RevokeAPIKeyInput{OwnerUserID: "other", ID: created.Key.ID}); !errors.Is(err, signet.ErrForbidden) {
		t.Fatalf("cross-owner revoke error = %v", err)
	}
}

func TestAPIKeyRawNotStored(t *testing.T) {
	store := newFakeAPIKeyStore()
	client := apiKeyClient(t, store, &fakeAuthorizer{allowed: map[string]bool{"api-keys:create": true}})
	created, err := client.CreateAPIKey(context.Background(), signet.CreateAPIKeyInput{OwnerUserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	for _, record := range store.keys {
		if strings.Contains(record.Hash, created.Raw) {
			t.Fatal("raw API key stored")
		}
	}
}
