// Package scim implements SCIM 2.0 provisioning behind optional adapters.
package scim

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"

	"github.com/elimity-com/scim"
	"github.com/elimity-com/scim/optional"
	"github.com/elimity-com/scim/schema"
	"github.com/shakibdshy/signet/internal/audit"
	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/secret"
)

// Service implements SCIM resource handlers and the mounted HTTP server.
type Service struct {
	cfg    *core.Config
	server scim.Server
	logger *slog.Logger
}

// New returns a Service; the SCIM server is mounted by the root Handler.
func New(cfg *core.Config, logger *slog.Logger) (*Service, error) {
	service := &Service{cfg: cfg, logger: logger}
	server, err := scim.NewServer(&scim.ServerArgs{
		ServiceProviderConfig: &scim.ServiceProviderConfig{
			SupportFiltering: false, SupportPatch: true, MaxResults: 100,
		},
		ResourceTypes: []scim.ResourceType{
			{
				Name: "User", Endpoint: "/Users", Schema: schema.CoreUserSchema(),
				Description: optional.NewString("Signet User"), Handler: &userHandler{service: service},
			},
			{
				Name: "Group", Endpoint: "/Groups", Schema: schema.CoreGroupSchema(),
				Description: optional.NewString("Directory Group"), Handler: &groupHandler{service: service},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	service.server = server
	return service, nil
}

// Enabled reports whether SCIM is configured.
func (s *Service) Enabled() bool { return s.cfg.SCIM != nil && s.cfg.SCIM.Store != nil }

// Handler returns the SCIM HTTP handler with bearer-token authentication.
func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Enabled() || !s.authorized(r) {
			s.emitDenied(r.Context())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		s.server.ServeHTTP(w, r)
	})
}

func (s *Service) authorized(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	presented := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if s.cfg.SCIM.Token == "" || presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.SCIM.Token)) == 1
}

func (s *Service) emitDenied(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	audit.Emit(ctx, s.cfg.AuditSink, s.logger, core.AuditEvent{Name: audit.SCIMUnauthorized, Outcome: "denied"})
}

func (s *Service) emit(ctx context.Context, name, userID string) {
	audit.Emit(ctx, s.cfg.AuditSink, s.logger, core.AuditEvent{Name: name, UserID: userID, Outcome: "success"})
}

func attributeString(attributes scim.ResourceAttributes, key string) string {
	value, ok := attributes[key]
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return text
}

func attributeBool(attributes scim.ResourceAttributes, key string) bool {
	value, ok := attributes[key]
	if !ok {
		return false
	}
	flag, _ := value.(bool)
	return flag
}

func attributeMembers(attributes scim.ResourceAttributes) []string {
	raw, ok := attributes["members"]
	if !ok {
		return nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	members := make([]string, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if value, ok := entry["value"].(string); ok && value != "" {
			members = append(members, value)
		}
	}
	return members
}

func emailAddress(attributes scim.ResourceAttributes) string {
	raw, ok := attributes["emails"]
	if !ok {
		return ""
	}
	items, ok := raw.([]interface{})
	if !ok || len(items) == 0 {
		return ""
	}
	entry, ok := items[0].(map[string]interface{})
	if !ok {
		return ""
	}
	value, _ := entry["value"].(string)
	return value
}

func resource(user *core.User) scim.Resource {
	return scim.Resource{
		ID: user.ID,
		Attributes: scim.ResourceAttributes{
			"userName": user.Email,
			"active":   !user.Disabled,
			"emails": []interface{}{map[string]interface{}{
				"value": user.Email, "primary": true,
			}},
		},
		Meta: scim.Meta{Created: &user.CreatedAt, LastModified: &user.UpdatedAt},
	}
}

type userHandler struct{ service *Service }

func (h *userHandler) Create(r *http.Request, attributes scim.ResourceAttributes) (scim.Resource, error) {
	email := emailAddress(attributes)
	if email == "" {
		email = attributeString(attributes, "userName")
	}
	if email == "" {
		return scim.Resource{}, core.ErrInvalidEmail
	}
	ctx := r.Context()
	store := h.service.cfg.SCIM.Store
	now := h.service.cfg.Clock.Now()
	user := &core.User{ID: secret.NewID(), Email: email, EmailVerified: true, CreatedAt: now, UpdatedAt: now}
	if err := h.service.cfg.Store.CreateUser(ctx, user); err != nil {
		return scim.Resource{}, err
	}
	if externalID := attributeString(attributes, "externalId"); externalID != "" {
		if err := store.SetUserExternalID(ctx, user.ID, externalID); err != nil {
			return scim.Resource{}, err
		}
	}
	h.service.emit(ctx, audit.SCIMUserCreated, user.ID)
	return resource(user), nil
}

func (h *userHandler) Get(r *http.Request, id string) (scim.Resource, error) {
	user, err := h.service.cfg.Store.UserByID(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	return resource(user), nil
}

func (h *userHandler) GetAll(r *http.Request, _ scim.ListRequestParams) (scim.Page, error) {
	users, err := h.service.cfg.SCIM.Store.ListUsers(r.Context())
	if err != nil {
		return scim.Page{}, err
	}
	resources := make([]scim.Resource, 0, len(users))
	for _, user := range users {
		resources = append(resources, resource(user))
	}
	return scim.Page{Resources: resources}, nil
}

func (h *userHandler) Replace(r *http.Request, id string, attributes scim.ResourceAttributes) (scim.Resource, error) {
	user, err := h.service.cfg.Store.UserByID(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	if email := emailAddress(attributes); email != "" {
		user.Email = email
	}
	user.Disabled = !attributeBool(attributes, "active") && !user.Disabled
	user.UpdatedAt = h.service.cfg.Clock.Now()
	if err := h.service.cfg.Store.UpdateUser(r.Context(), user); err != nil {
		return scim.Resource{}, err
	}
	h.service.emit(r.Context(), audit.SCIMUserUpdated, user.ID)
	return resource(user), nil
}

func (h *userHandler) Delete(r *http.Request, id string) error {
	if err := h.service.cfg.Store.DeleteUser(r.Context(), id); err != nil {
		return err
	}
	h.service.emit(r.Context(), audit.SCIMUserDeleted, id)
	return nil
}

func (h *userHandler) Patch(r *http.Request, id string, operations []scim.PatchOperation) (scim.Resource, error) {
	user, err := h.service.cfg.Store.UserByID(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	for _, operation := range operations {
		if !strings.EqualFold(operation.Op, "replace") {
			continue
		}
		values, ok := operation.Value.(map[string]interface{})
		if !ok {
			continue
		}
		for key, value := range values {
			if key == "active" {
				flag, _ := value.(bool)
				user.Disabled = !flag
			}
		}
	}
	user.UpdatedAt = h.service.cfg.Clock.Now()
	if err := h.service.cfg.Store.UpdateUser(r.Context(), user); err != nil {
		return scim.Resource{}, err
	}
	h.service.emit(r.Context(), audit.SCIMUserUpdated, user.ID)
	return resource(user), nil
}

type groupHandler struct{ service *Service }

func (h *groupHandler) Create(r *http.Request, attributes scim.ResourceAttributes) (scim.Resource, error) {
	group := &core.SCIMGroup{
		ID: secret.NewID(), ExternalID: attributeString(attributes, "externalId"),
		DisplayName: attributeString(attributes, "displayName"), Members: attributeMembers(attributes),
	}
	if err := h.service.cfg.SCIM.Store.CreateGroup(r.Context(), group); err != nil {
		return scim.Resource{}, err
	}
	if projector := h.service.cfg.SCIM.Projector; projector != nil {
		if err := projector(r.Context(), group); err != nil {
			return scim.Resource{}, err
		}
	}
	h.service.emit(r.Context(), audit.SCIMGroupCreated, group.ID)
	return groupResource(group), nil
}

func (h *groupHandler) Get(r *http.Request, id string) (scim.Resource, error) {
	group, err := h.service.cfg.SCIM.Store.GroupByID(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	return groupResource(group), nil
}

func (h *groupHandler) GetAll(r *http.Request, _ scim.ListRequestParams) (scim.Page, error) {
	groups, err := h.service.cfg.SCIM.Store.ListGroups(r.Context())
	if err != nil {
		return scim.Page{}, err
	}
	resources := make([]scim.Resource, 0, len(groups))
	for _, group := range groups {
		resources = append(resources, groupResource(group))
	}
	return scim.Page{Resources: resources}, nil
}

func (h *groupHandler) Replace(r *http.Request, id string, attributes scim.ResourceAttributes) (scim.Resource, error) {
	group, err := h.service.cfg.SCIM.Store.GroupByID(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	group.DisplayName = attributeString(attributes, "displayName")
	group.Members = attributeMembers(attributes)
	if err := h.service.cfg.SCIM.Store.UpdateGroup(r.Context(), group); err != nil {
		return scim.Resource{}, err
	}
	if projector := h.service.cfg.SCIM.Projector; projector != nil {
		if err := projector(r.Context(), group); err != nil {
			return scim.Resource{}, err
		}
	}
	h.service.emit(r.Context(), audit.SCIMGroupUpdated, group.ID)
	return groupResource(group), nil
}

func (h *groupHandler) Delete(r *http.Request, id string) error {
	if err := h.service.cfg.SCIM.Store.DeleteGroup(r.Context(), id); err != nil {
		return err
	}
	h.service.emit(r.Context(), audit.SCIMGroupDeleted, id)
	return nil
}

func (h *groupHandler) Patch(r *http.Request, id string, operations []scim.PatchOperation) (scim.Resource, error) {
	group, err := h.service.cfg.SCIM.Store.GroupByID(r.Context(), id)
	if err != nil {
		return scim.Resource{}, err
	}
	for _, operation := range operations {
		if strings.EqualFold(operation.Op, "replace") {
			if values, ok := operation.Value.(map[string]interface{}); ok {
				if raw, ok := values["members"]; ok {
					group.Members = attributeMembers(scim.ResourceAttributes{"members": raw})
				}
			}
		}
	}
	if err := h.service.cfg.SCIM.Store.UpdateGroup(r.Context(), group); err != nil {
		return scim.Resource{}, err
	}
	return groupResource(group), nil
}

func groupResource(group *core.SCIMGroup) scim.Resource {
	members := make([]interface{}, 0, len(group.Members))
	for _, member := range group.Members {
		members = append(members, map[string]interface{}{"value": member})
	}
	return scim.Resource{
		ID: group.ID, ExternalID: optional.NewString(group.ExternalID),
		Attributes: scim.ResourceAttributes{
			"displayName": group.DisplayName, "members": members,
		},
		Meta: scim.Meta{},
	}
}
