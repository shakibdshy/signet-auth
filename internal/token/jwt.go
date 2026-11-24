package token

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shakibdshy/signet-auth/internal/audit"
	"github.com/shakibdshy/signet-auth/internal/core"
	"github.com/shakibdshy/signet-auth/internal/secret"
)

const (
	defaultAccessTTL  = 15 * time.Minute
	defaultRefreshTTL = 30 * 24 * time.Hour
)

type jwtAlgorithm struct {
	method   jwt.SigningMethod
	validKey func(any) bool
}

var jwtAlgorithms = map[string]jwtAlgorithm{
	"HS256": {jwt.SigningMethodHS256, func(key any) bool { _, ok := key.([]byte); return ok }},
	"RS256": {jwt.SigningMethodRS256, func(key any) bool { _, ok := key.(*rsa.PrivateKey); return ok }},
	"EdDSA": {jwt.SigningMethodEdDSA, func(key any) bool { _, ok := key.(ed25519.PrivateKey); return ok }},
}

// ValidateJWTConfig checks the algorithm and key and fills default TTLs.
func ValidateJWTConfig(cfg *core.JWTConfig) error {
	algorithm, ok := jwtAlgorithms[cfg.Algorithm]
	if !ok {
		return core.ErrInvalidJWTAlgorithm
	}
	keys := cfg.Keys
	if len(keys) > 0 && cfg.Key != nil {
		return core.ErrInvalidKeyRing
	}
	if len(keys) == 0 {
		if cfg.Key == nil {
			return core.ErrInvalidKeyRing
		}
		keys = []any{cfg.Key}
	}
	for i, key := range keys {
		if !algorithm.validKey(key) {
			if len(cfg.Keys) > 0 {
				return core.ErrInvalidKeyRing
			}
			return core.ErrInvalidJWTKey
		}
		for _, earlier := range keys[:i] {
			if reflect.DeepEqual(earlier, key) {
				return core.ErrInvalidKeyRing
			}
		}
	}
	cfg.Key = keys[0]
	if cfg.AccessTTL == 0 {
		cfg.AccessTTL = defaultAccessTTL
	}
	if cfg.RefreshTTL == 0 {
		cfg.RefreshTTL = defaultRefreshTTL
	}
	return nil
}

// VerificationKeys returns every key that should verify an Access token.
func VerificationKeys(cfg *core.JWTConfig) []any {
	if len(cfg.Keys) > 0 {
		return cfg.Keys
	}
	if cfg.Key != nil {
		return []any{cfg.Key}
	}
	return nil
}

// JWTDependencies holds the resolved configuration and collaborators the JWT
// service needs.
type JWTDependencies struct {
	Config          *core.JWTConfig
	Store           core.Store
	Clock           core.Clock
	Limiter         core.RateLimiter
	Logger          *slog.Logger
	SignIn          func(context.Context, core.SignInInput) (*core.SignInResult, error)
	RevokeSessions  func(context.Context, string) error
	VerifyTwoFactor func(context.Context, core.VerifyTwoFactorInput) (*core.SignInResult, error)
	AuditSink       core.AuditSink
	Tokens          *Service
}

// JWTService implements Signet's optional bearer-token mode.
type JWTService struct {
	deps       JWTDependencies
	verifyKeys []any
}

// NewJWT returns a JWTService.
func NewJWT(deps JWTDependencies) *JWTService {
	return &JWTService{deps: deps, verifyKeys: VerificationKeys(deps.Config)}
}

// SetVerifyTwoFactor wires the Second factor callback after the auth service exists.
func (s *JWTService) SetVerifyTwoFactor(fn func(context.Context, core.VerifyTwoFactorInput) (*core.SignInResult, error)) {
	s.deps.VerifyTwoFactor = fn
}

func (s *JWTService) allow(ctx context.Context, endpoint, key string) error {
	if key == "" {
		key = "local"
	}
	allowed, err := s.deps.Limiter.Allow(ctx, endpoint+"|"+key)
	if err != nil {
		return err
	}
	if !allowed {
		return core.ErrRateLimited
	}
	return nil
}

func (s *JWTService) logWarn(msg string, attrs ...any) {
	s.deps.Logger.Warn(msg, append([]any{"at", s.deps.Clock.Now()}, attrs...)...)
}

// Exchange issues a TokenPair for credentials, or rotates a Refresh token.
func (s *JWTService) Exchange(ctx context.Context, in core.TokenInput) (*core.TokenPair, error) {
	if s.deps.Config == nil {
		return nil, core.ErrJWTDisabled
	}
	if in.RefreshToken != "" {
		if err := s.allow(ctx, "token", in.RateLimitKey); err != nil {
			return nil, err
		}
		return s.refreshTokens(ctx, in.RefreshToken)
	}
	if in.Challenge != "" || in.Code != "" {
		if s.deps.VerifyTwoFactor == nil || in.Challenge == "" || in.Code == "" {
			return nil, core.ErrTokenInvalid
		}
		result, err := s.deps.VerifyTwoFactor(ctx, core.VerifyTwoFactorInput{
			Challenge: in.Challenge, Code: in.Code, RateLimitKey: in.RateLimitKey,
		})
		if err != nil {
			return nil, err
		}
		return s.Issue(ctx, result.User.ID)
	}
	result, err := s.deps.SignIn(ctx, core.SignInInput{
		Email: in.Email, Password: in.Password, RateLimitKey: in.RateLimitKey,
	})
	if err != nil {
		return nil, err
	}
	if result.TwoFactorChallenge != "" {
		return &core.TokenPair{TwoFactorChallenge: result.TwoFactorChallenge, LastSignInMethod: result.LastSignInMethod}, nil
	}
	pair, err := s.Issue(ctx, result.User.ID)
	if err != nil {
		return nil, err
	}
	pair.LastSignInMethod = result.LastSignInMethod
	return pair, nil
}

// VerifyAccessToken validates a bearer token and returns its User.
func (s *JWTService) VerifyAccessToken(ctx context.Context, raw string) (*core.User, error) {
	if s.deps.Config == nil {
		return nil, core.ErrJWTDisabled
	}
	keys := s.verifyKeys
	if len(keys) == 0 {
		return nil, core.ErrTokenInvalid
	}
	var claims *jwt.RegisteredClaims
	var parsed *jwt.Token
	var err error
	for _, key := range keys {
		candidate := &jwt.RegisteredClaims{}
		token, parseErr := jwt.ParseWithClaims(raw, candidate, func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != s.deps.Config.Algorithm {
				return nil, core.ErrInvalidJWTAlgorithm
			}
			return key, nil
		}, jwt.WithValidMethods([]string{s.deps.Config.Algorithm}))
		if parseErr == nil && token.Valid {
			claims, parsed, err = candidate, token, nil
			break
		}
		err = parseErr
	}
	if claims == nil || parsed == nil || err != nil {
		return nil, core.ErrTokenInvalid
	}
	if s.deps.Config.Issuer != "" && claims.Issuer != s.deps.Config.Issuer {
		return nil, core.ErrTokenInvalid
	}
	return s.deps.Store.UserByID(ctx, claims.Subject)
}

// IssueWithScope signs an Access token carrying OAuth scope and audience
// claims and stores a rotating Refresh proof carrying the same claims.
func (s *JWTService) IssueWithScope(ctx context.Context, userID, audience string, scopes []string) (*core.TokenPair, error) {
	now := s.deps.Clock.Now()
	claims := jwt.MapClaims{
		"sub":   userID,
		"iat":   now.Unix(),
		"exp":   now.Add(s.deps.Config.AccessTTL).Unix(),
		"scope": strings.Join(scopes, " "),
	}
	if audience != "" {
		claims["aud"] = audience
	}
	if s.deps.Config.Issuer != "" {
		claims["iss"] = s.deps.Config.Issuer
	}
	algorithm, ok := jwtAlgorithms[s.deps.Config.Algorithm]
	if !ok {
		return nil, core.ErrInvalidJWTAlgorithm
	}
	signed := jwt.NewWithClaims(algorithm.method, claims)
	switch s.deps.Config.Key.(type) {
	case *rsa.PrivateKey, ed25519.PrivateKey:
		kid, err := keyID(s.deps.Config.Key)
		if err != nil {
			return nil, err
		}
		signed.Header["kid"] = kid
	}
	access, err := signed.SignedString(s.deps.Config.Key)
	if err != nil {
		return nil, err
	}
	data, _ := json.Marshal(struct {
		Audience string   `json:"audience"`
		Scopes   []string `json:"scopes"`
	}{audience, scopes})
	raw, _, err := s.deps.Tokens.IssueWithData(ctx, userID, core.TokenRefresh, s.deps.Config.RefreshTTL, string(data))
	if err != nil {
		return nil, err
	}
	return &core.TokenPair{
		AccessToken:  access,
		RefreshToken: raw,
		ExpiresIn:    int64(s.deps.Config.AccessTTL / time.Second),
	}, nil
}

// RefreshWithScope rotates a Refresh proof, preserving its scope and audience.
func (s *JWTService) RefreshWithScope(ctx context.Context, presented string) (*core.TokenPair, error) {
	digest := secret.Digest(presented)
	token, err := s.deps.Store.TokenByHash(ctx, core.TokenRefresh, digest)
	if errors.Is(err, core.ErrNotFound) {
		return nil, core.ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	if token.UsedAt != nil {
		return s.handleRefreshReuse(ctx, token.UserID)
	}
	if !s.deps.Clock.Now().Before(token.ExpiresAt) {
		return nil, core.ErrTokenExpired
	}
	consumed, err := s.deps.Store.ConsumeToken(ctx, core.TokenRefresh, digest)
	if errors.Is(err, core.ErrNotFound) {
		return s.handleRefreshReuse(ctx, token.UserID)
	}
	if err != nil {
		return nil, err
	}
	user, err := s.deps.Store.UserByID(ctx, consumed.UserID)
	if err != nil {
		return nil, err
	}
	if user.Disabled {
		return nil, core.ErrInvalidCredentials
	}
	var data struct {
		Audience string   `json:"audience"`
		Scopes   []string `json:"scopes"`
	}
	if raw, err := ParseData(presented); err == nil {
		_ = json.Unmarshal([]byte(raw), &data)
	}
	return s.IssueWithScope(ctx, user.ID, data.Audience, data.Scopes)
}

// Issue signs a fresh Access token and stores a rotating Refresh proof.
func (s *JWTService) Issue(ctx context.Context, userID string) (*core.TokenPair, error) {
	return s.IssueWithScope(ctx, userID, "", nil)
}

func (s *JWTService) refreshTokens(ctx context.Context, presented string) (*core.TokenPair, error) {
	return s.RefreshWithScope(ctx, presented)
}

func (s *JWTService) handleRefreshReuse(ctx context.Context, userID string) (*core.TokenPair, error) {
	_ = s.deps.RevokeSessions(ctx, userID)
	for _, kind := range core.AllTokenKinds {
		_ = s.deps.Store.DeleteTokensForUser(ctx, userID, kind)
	}
	s.logWarn("refresh_token_reuse", "user_id", userID)
	audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.RefreshReuse, UserID: userID, Outcome: "blocked"})
	return nil, core.ErrRefreshReuse
}
