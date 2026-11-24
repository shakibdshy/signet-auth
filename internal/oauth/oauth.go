// Package oauth implements Signet's Authorization Code flow with PKCE.
package oauth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/shakibdshy/signet-auth/internal/audit"
	"github.com/shakibdshy/signet-auth/internal/core"
	"github.com/shakibdshy/signet-auth/internal/secret"
	"github.com/shakibdshy/signet-auth/internal/session"
	"github.com/shakibdshy/signet-auth/internal/token"
)

const (
	stateTTL = 10 * time.Minute
	linkTTL  = 10 * time.Minute
)

type statePayload struct {
	Provider  string    `json:"provider"`
	Redirect  string    `json:"redirect"`
	Verifier  string    `json:"verifier"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

type linkPayload struct {
	Identity  core.OAuthIdentity `json:"identity"`
	ExpiresAt time.Time          `json:"expires_at"`
}

// Service implements the OAuth start, callback and link flows.
type Service struct {
	cfg       *core.OAuthConfig
	patterns  []string
	store     core.Store
	clock     core.Clock
	limiter   core.RateLimiter
	logger    *slog.Logger
	auditSink core.AuditSink
	tokens    *token.Service
	sessions  *session.Service
}

// New returns an OAuth Service.
func New(cfg *core.OAuthConfig, patterns []string, store core.Store, clock core.Clock, limiter core.RateLimiter, logger *slog.Logger, tokens *token.Service, sessions *session.Service, sink core.AuditSink) *Service {
	return &Service{cfg: cfg, patterns: patterns, store: store, clock: clock, limiter: limiter, logger: logger, tokens: tokens, sessions: sessions, auditSink: sink}
}

func (s *Service) logInfo(msg string, attrs ...any) {
	s.logger.Info(msg, append([]any{"at", s.clock.Now()}, attrs...)...)
}

func (s *Service) allow(ctx context.Context, endpoint, key string) error {
	if key == "" {
		key = "local"
	}
	ok, err := s.limiter.Allow(ctx, endpoint+"|"+key)
	if err != nil {
		return err
	}
	if !ok {
		return core.ErrRateLimited
	}
	return nil
}

func (s *Service) provider(name string) core.OAuthProvider {
	for _, p := range s.cfg.Providers {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

func (s *Service) redirectAllowed(redirect string) bool {
	return core.RedirectPermitted(redirect, s.cfg.AllowedRedirects, s.patterns)
}

func (s *Service) seal(value any) (string, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.cfg.StateKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Service) open(raw string, out any) error {
	sealed, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return core.ErrOAuthInvalidState
	}
	block, err := aes.NewCipher(s.cfg.StateKey)
	if err != nil {
		return core.ErrOAuthInvalidState
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return core.ErrOAuthInvalidState
	}
	if len(sealed) < gcm.NonceSize() {
		return core.ErrOAuthInvalidState
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return core.ErrOAuthInvalidState
	}
	if err := json.Unmarshal(plaintext, out); err != nil {
		return core.ErrOAuthInvalidState
	}
	return nil
}

// Start begins the flow and returns the provider authorization URL.
func (s *Service) Start(ctx context.Context, in core.OAuthStartInput) (*core.OAuthStartResult, error) {
	if err := s.allow(ctx, "oauth/start", in.RateLimitKey); err != nil {
		return nil, err
	}
	if !s.redirectAllowed(in.Redirect) {
		return nil, core.ErrOAuthRedirectNotAllowed
	}
	provider := s.provider(in.Provider)
	if provider == nil {
		return nil, core.ErrOAuthProviderNotFound
	}
	verifier := secret.NewToken()
	nonce := secret.NewToken()
	challengeSum := sha256Sum(verifier)
	state, err := s.seal(statePayload{
		Provider: in.Provider, Redirect: in.Redirect,
		Verifier: verifier, Nonce: nonce,
		ExpiresAt: s.clock.Now().Add(stateTTL),
	})
	if err != nil {
		return nil, err
	}
	if err := s.store.CreateToken(ctx, &core.Token{
		ID: secret.NewID(), Kind: core.TokenOAuthState, Hash: secret.Digest(state),
		ExpiresAt: s.clock.Now().Add(stateTTL), CreatedAt: s.clock.Now(),
	}); err != nil {
		return nil, err
	}
	redirectURI := strings.TrimRight(s.cfg.RedirectBaseURL, "/") + "/oauth/callback"
	var authURL string
	if withNonce, ok := provider.(core.AuthURLWithNonce); ok {
		authURL = withNonce.AuthURLWithNonce("", redirectURI, state, challengeSum, nonce)
	} else {
		authURL = provider.AuthURL("", redirectURI, state, challengeSum)
	}
	s.logInfo("oauth/start", "provider", in.Provider)
	return &core.OAuthStartResult{URL: authURL}, nil
}

// Callback redeems the provider code and returns the signed-in User, or a
// one-time link token when the provider email is unverified.
func (s *Service) Callback(ctx context.Context, in core.OAuthCallbackInput) (*core.OAuthCallbackResult, error) {
	if err := s.allow(ctx, "oauth/callback", in.RateLimitKey); err != nil {
		return nil, err
	}
	if _, err := s.tokens.Consume(ctx, core.TokenOAuthState, in.State); err != nil {
		if errors.Is(err, core.ErrTokenInvalid) || errors.Is(err, core.ErrTokenExpired) {
			return nil, core.ErrOAuthInvalidState
		}
		return nil, err
	}
	var state statePayload
	if err := s.open(in.State, &state); err != nil {
		return nil, err
	}
	if !s.clock.Now().Before(state.ExpiresAt) {
		return nil, core.ErrOAuthInvalidState
	}
	provider := s.provider(state.Provider)
	if provider == nil {
		return nil, core.ErrOAuthProviderNotFound
	}
	if !s.redirectAllowed(state.Redirect) {
		return nil, core.ErrOAuthRedirectNotAllowed
	}
	redirectURI := strings.TrimRight(s.cfg.RedirectBaseURL, "/") + "/oauth/callback"
	var identity *core.OAuthIdentity
	var err error
	if withNonce, ok := provider.(core.ExchangeWithNonce); ok {
		identity, err = withNonce.ExchangeWithNonce(ctx, in.Code, state.Verifier, redirectURI, state.Nonce)
	} else {
		identity, err = provider.Exchange(ctx, in.Code, state.Verifier, redirectURI)
	}
	if err != nil {
		return nil, err
	}
	if !identity.EmailVerified {
		return s.pendingLink(ctx, identity, state.Redirect)
	}
	user, err := s.linkOrCreateUser(ctx, identity)
	if err != nil {
		return nil, err
	}
	sessionToken, err := s.sessions.Create(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	s.logInfo("oauth_sign_in", "user_id", user.ID, "provider", identity.Provider)
	audit.Emit(ctx, s.auditSink, s.logger, core.AuditEvent{Name: audit.OAuthSignIn, UserID: user.ID, Outcome: "success", Metadata: map[string]string{"provider": identity.Provider}})
	return &core.OAuthCallbackResult{LastSignInMethod: identity.Provider, User: user, SessionToken: sessionToken, Redirect: state.Redirect}, nil
}

func (s *Service) pendingLink(ctx context.Context, identity *core.OAuthIdentity, redirect string) (*core.OAuthCallbackResult, error) {
	link, err := s.seal(linkPayload{Identity: *identity, ExpiresAt: s.clock.Now().Add(linkTTL)})
	if err != nil {
		return nil, err
	}
	if err := s.store.CreateToken(ctx, &core.Token{
		ID: secret.NewID(), Kind: core.TokenOAuthLink, Hash: secret.Digest(link),
		ExpiresAt: s.clock.Now().Add(linkTTL), CreatedAt: s.clock.Now(),
	}); err != nil {
		return nil, err
	}
	s.logInfo("oauth_link_required", "provider", identity.Provider)
	return &core.OAuthCallbackResult{LinkToken: link, Redirect: redirect}, nil
}

func (s *Service) linkOrCreateUser(ctx context.Context, identity *core.OAuthIdentity) (*core.User, error) {
	email := strings.ToLower(strings.TrimSpace(identity.Email))
	if email == "" {
		return nil, core.ErrOAuthEmailNotVerified
	}
	user, err := s.store.UserByEmail(ctx, email)
	if err == nil {
		if err := s.linkAccount(ctx, user, identity); err != nil {
			return nil, err
		}
		return user, nil
	}
	if !errors.Is(err, core.ErrNotFound) {
		return nil, err
	}
	now := s.clock.Now()
	user = &core.User{ID: secret.NewID(), Email: email, EmailVerified: true, CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	if err := s.linkAccount(ctx, user, identity); err != nil {
		_ = s.store.DeleteUser(ctx, user.ID)
		return nil, err
	}
	s.logInfo("oauth_user_created", "user_id", user.ID)
	return user, nil
}

func (s *Service) linkAccount(ctx context.Context, user *core.User, identity *core.OAuthIdentity) error {
	existing, err := s.store.AccountByProvider(ctx, identity.Provider, identity.ProviderUserID)
	if err == nil {
		if existing.UserID != user.ID {
			return core.ErrOAuthAccountConflict
		}
		return nil
	}
	if !errors.Is(err, core.ErrNotFound) {
		return err
	}
	return s.store.CreateAccount(ctx, &core.Account{
		ID: secret.NewID(), UserID: user.ID, Provider: identity.Provider,
		ProviderUserID: identity.ProviderUserID, Email: strings.ToLower(strings.TrimSpace(identity.Email)),
		EmailVerified: identity.EmailVerified, CreatedAt: s.clock.Now(),
	})
}

// LinkAccount consumes a link token for an authenticated User.
func (s *Service) LinkAccount(ctx context.Context, in core.LinkOAuthAccountInput) error {
	var payload linkPayload
	if err := s.open(in.LinkToken, &payload); err != nil {
		// A corrupt or tampered link token is reported like any other bad
		// Token, matching the pre-refactor openLink mapping.
		return core.ErrTokenInvalid
	}
	if !s.clock.Now().Before(payload.ExpiresAt) {
		return core.ErrTokenInvalid
	}
	if _, err := s.tokens.Consume(ctx, core.TokenOAuthLink, in.LinkToken); err != nil {
		return err
	}
	user, err := s.store.UserByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	if err := s.linkAccount(ctx, user, &payload.Identity); err != nil {
		return err
	}
	s.logInfo("oauth_link", "user_id", user.ID, "provider", payload.Identity.Provider)
	return nil
}

func sha256Sum(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
