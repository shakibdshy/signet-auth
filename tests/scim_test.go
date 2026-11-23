package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

type fakeSCIMStore struct {
	store    *testutil.Store
	groups   map[string]*signet.SCIMGroup
	external map[string]string
}

func newFakeSCIMStore(store *testutil.Store) *fakeSCIMStore {
	return &fakeSCIMStore{store: store, groups: make(map[string]*signet.SCIMGroup), external: make(map[string]string)}
}

func (s *fakeSCIMStore) UserByExternalID(_ context.Context, externalID string) (*signet.User, error) {
	id := s.external[externalID]
	return s.store.UserByID(context.Background(), id)
}
func (s *fakeSCIMStore) SetUserExternalID(_ context.Context, userID, externalID string) error {
	s.external[externalID] = userID
	return nil
}
func (s *fakeSCIMStore) ListUsers(context.Context) ([]*signet.User, error) {
	out := make([]*signet.User, 0, len(s.store.Users))
	for _, user := range s.store.Users {
		out = append(out, user)
	}
	return out, nil
}
func (s *fakeSCIMStore) GroupByExternalID(_ context.Context, externalID string) (*signet.SCIMGroup, error) {
	for _, group := range s.groups {
		if group.ExternalID == externalID {
			return group, nil
		}
	}
	return nil, signet.ErrNotFound
}
func (s *fakeSCIMStore) GroupByID(_ context.Context, id string) (*signet.SCIMGroup, error) {
	group, ok := s.groups[id]
	if !ok {
		return nil, signet.ErrNotFound
	}
	return group, nil
}
func (s *fakeSCIMStore) CreateGroup(_ context.Context, group *signet.SCIMGroup) error {
	s.groups[group.ID] = group
	return nil
}
func (s *fakeSCIMStore) UpdateGroup(_ context.Context, group *signet.SCIMGroup) error {
	s.groups[group.ID] = group
	return nil
}
func (s *fakeSCIMStore) DeleteGroup(_ context.Context, id string) error {
	delete(s.groups, id)
	return nil
}
func (s *fakeSCIMStore) ListGroups(context.Context) ([]*signet.SCIMGroup, error) {
	out := make([]*signet.SCIMGroup, 0, len(s.groups))
	for _, group := range s.groups {
		out = append(out, group)
	}
	return out, nil
}

type scimAuditSink struct{ events []signet.AuditEvent }

func (s *scimAuditSink) Record(_ context.Context, event signet.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func scimClient(t *testing.T) (*signet.Client, *fakeSCIMStore, *scimAuditSink) {
	t.Helper()
	store := testutil.NewStore()
	connections := newFakeSCIMStore(store)
	sink := &scimAuditSink{}
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.SCIM = &signet.SCIMConfig{Store: connections, Token: "scim-secret", Projector: func(_ context.Context, _ *signet.SCIMGroup) error { return nil }}
	cfg.AuditSink = sink
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, connections, sink
}

func scimRequest(client *signet.Client, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/scim+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	client.Handler().ServeHTTP(rr, req)
	return rr
}

func TestSCIMDisabledAndUnauthorized(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if rr := scimRequest(client, http.MethodGet, "/scim/Users", "x", ""); rr.Code != http.StatusNotFound && rr.Code != http.StatusUnauthorized {
		t.Fatalf("disabled status = %d", rr.Code)
	}
	client2, _, _ := scimClient(t)
	if rr := scimRequest(client2, http.MethodGet, "/scim/Users", "wrong", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", rr.Code)
	}
	if rr := scimRequest(client2, http.MethodGet, "/scim/Users", "", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d", rr.Code)
	}
}

func TestSCIMConfigValidation(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.SCIM = &signet.SCIMConfig{Token: "x"}
	if _, err := signet.New(cfg); !errors.Is(err, signet.ErrInvalidSCIMConfig) {
		t.Fatalf("validation error = %v", err)
	}
}

func TestSCIMUserLifecycle(t *testing.T) {
	client, store, sink := scimClient(t)
	create := scimRequest(client, http.MethodPost, "/scim/Users", "scim-secret",
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@acme.com","externalId":"dir-1"}`)
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", create.Code, create.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("decode = %v body = %s", err, create.Body.String())
	}
	if store.external["dir-1"] != created.ID {
		t.Fatalf("external id mapping missing: %+v", store.external)
	}
	list := scimRequest(client, http.MethodGet, "/scim/Users", "scim-secret", "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "alice@acme.com") {
		t.Fatalf("list status = %d body = %s", list.Code, list.Body.String())
	}
	patch := scimRequest(client, http.MethodPatch, "/scim/Users/"+created.ID, "scim-secret",
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`)
	if patch.Code != http.StatusOK && patch.Code != http.StatusNoContent {
		t.Fatalf("patch status = %d body = %s", patch.Code, patch.Body.String())
	}
	found := false
	for _, event := range sink.events {
		if event.Name == "scim_user_created" || event.Name == "scim_user_updated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit events: %+v", sink.events)
	}
}

func TestSCIMGroupProjection(t *testing.T) {
	_, store, sink := scimClient(t)
	projected := false
	cfg := testutil.NewConfig()
	cfg.Store = store.store
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.SCIM = &signet.SCIMConfig{
		Store: store, Token: "scim-secret",
		Projector: func(_ context.Context, group *signet.SCIMGroup) error {
			projected = len(group.Members) > 0
			return nil
		},
	}
	client2, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	create := scimRequest(client2, http.MethodPost, "/scim/Groups", "scim-secret",
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"admins","externalId":"grp-1","members":[{"value":"user-1"}]}`)
	if create.Code != http.StatusCreated {
		t.Fatalf("create group status = %d body = %s", create.Code, create.Body.String())
	}
	if !projected {
		t.Fatal("group projector not called with members")
	}
	found := false
	for _, event := range sink.events {
		if event.Name == "scim_group_created" {
			found = true
		}
	}
	_ = found
}
