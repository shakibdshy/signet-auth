package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: TOTP requires HMAC-SHA1.
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/shakibdshy/signet-auth/internal/audit"
	"github.com/shakibdshy/signet-auth/internal/core"
	"github.com/shakibdshy/signet-auth/internal/secret"
	"github.com/shakibdshy/signet-auth/internal/token"
)

const (
	backupCodeCount = 10
	challengeTTL    = 5 * time.Minute
	backupCharset   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func (s *Service) requireTOTP() error {
	if s.deps.TOTPStore == nil || len(s.deps.TOTPKey) != 32 {
		return core.ErrTOTPNotConfigured
	}
	return nil
}

func (s *Service) aead() (cipher.AEAD, error) {
	sum := sha256.Sum256(s.deps.TOTPKey)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Service) encrypt(plaintext string) (string, error) {
	aead, err := s.aead()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Service) decrypt(encoded string) (string, error) {
	aead, err := s.aead()
	if err != nil {
		return "", err
	}
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(sealed) < aead.NonceSize() {
		return "", core.ErrTOTPInvalid
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", core.ErrTOTPInvalid
	}
	return string(plaintext), nil
}

func newSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func totpAt(secret string, at time.Time, digits, period int) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	counter := uint64(at.Unix() / int64(period)) //nolint:gosec // TOTP counters are non-negative in practice.
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for i := 0; i < digits; i++ {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%modulus)
}

func (s *Service) codeMatches(secret, presented string) bool {
	if presented == "" {
		return false
	}
	cfg := s.deps.TOTP
	window := cfg.Window
	for delta := -window; delta <= window; delta++ {
		candidate := totpAt(secret, s.deps.Clock.Now().Add(time.Duration(delta*cfg.Period)*time.Second), cfg.Digits, cfg.Period)
		if subtleCompare(candidate, presented) {
			return true
		}
	}
	return false
}

func subtleCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return hmac.Equal([]byte(a), []byte(b))
}

func backupCode() (string, error) {
	var out strings.Builder
	for i := 0; i < 10; i++ {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(backupCharset))))
		if err != nil {
			return "", err
		}
		out.WriteByte(backupCharset[index.Int64()])
		if i == 4 {
			out.WriteByte('-')
		}
	}
	return out.String(), nil
}

func (s *Service) newBackupCodes() ([]string, []string, error) {
	raw := make([]string, 0, backupCodeCount)
	digests := make([]string, 0, backupCodeCount)
	for i := 0; i < backupCodeCount; i++ {
		code, err := backupCode()
		if err != nil {
			return nil, nil, err
		}
		raw = append(raw, code)
		digests = append(digests, secret.Digest(code))
	}
	return raw, digests, nil
}

func (s *Service) verifyPassword(ctx context.Context, userID, password string) error {
	account, err := s.deps.Store.AccountByProvider(ctx, credentialProvider, userID)
	if err != nil {
		return core.ErrInvalidCredentials
	}
	ok, err := s.deps.Hasher.Verify(ctx, account.PasswordHash, password)
	if err != nil || !ok {
		return core.ErrInvalidCredentials
	}
	return nil
}

func (s *Service) provisioningURI(email, secret string) string {
	cfg := s.deps.TOTP
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = s.deps.AppURL
	}
	label := url.QueryEscape(issuer + ":" + email)
	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", fmt.Sprintf("%d", cfg.Digits))
	query.Set("period", fmt.Sprintf("%d", cfg.Period))
	return "otpauth://totp/" + label + "?" + query.Encode()
}

// EnableTwoFactor starts enrollment. It returns the provisioning URI and
// Backup codes, but leaves the enrollment pending until a code is verified.
func (s *Service) EnableTwoFactor(ctx context.Context, in core.EnableTwoFactorInput) (*core.EnableTwoFactorResult, error) {
	if err := s.requireTOTP(); err != nil {
		return nil, err
	}
	if err := s.allow(ctx, "enable-two-factor", in.RateLimitKey); err != nil {
		return nil, err
	}
	userID := in.UserID
	if userID == "" {
		return nil, core.ErrInvalidCredentials
	}
	if err := s.verifyPassword(ctx, userID, in.Password); err != nil {
		return nil, err
	}
	if _, err := s.deps.TOTPStore.Get(ctx, userID); err == nil {
		return nil, core.ErrTOTPInvalid
	} else if !errors.Is(err, core.ErrNotFound) {
		return nil, err
	}
	rawSecret, err := newSecret()
	if err != nil {
		return nil, err
	}
	encrypted, err := s.encrypt(rawSecret)
	if err != nil {
		return nil, err
	}
	codes, digests, err := s.newBackupCodes()
	if err != nil {
		return nil, err
	}
	if err := s.deps.TOTPStore.Put(ctx, userID, &core.TOTPState{Secret: encrypted, BackupCodes: digests}); err != nil {
		return nil, err
	}
	challenge, _, err := s.deps.Tokens.IssueWithData(ctx, userID, core.TokenTwoFactor, challengeTTL, "password")
	if err != nil {
		return nil, err
	}
	user, err := s.deps.Store.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	s.logInfo("two_factor_enabled_pending", "user_id", userID)
	return &core.EnableTwoFactorResult{
		TOTPURI: s.provisioningURI(user.Email, rawSecret), Challenge: challenge, BackupCodes: codes,
	}, nil
}

// VerifyTwoFactor exchanges a Two-factor challenge for a Session.
func (s *Service) VerifyTwoFactor(ctx context.Context, in core.VerifyTwoFactorInput) (*core.SignInResult, error) {
	if err := s.requireTOTP(); err != nil {
		return nil, err
	}
	if in.Challenge == "" || in.Code == "" {
		return nil, core.ErrTokenInvalid
	}
	proof, err := s.deps.Tokens.ByHash(ctx, core.TokenTwoFactor, in.Challenge)
	if err != nil {
		return nil, err
	}
	// Throttle before consuming: a wrong guess must not burn the challenge,
	// otherwise the attempt cap could never be reached.
	if err := s.allow(ctx, "verify-two-factor", secret.Digest(in.Challenge)); err != nil {
		return nil, err
	}
	state, err := s.deps.TOTPStore.Get(ctx, proof.UserID)
	if err != nil {
		return nil, core.ErrTOTPNotEnabled
	}
	plainSecret, err := s.decrypt(state.Secret)
	if err != nil {
		return nil, err
	}
	if !state.Verified {
		if !s.codeMatches(plainSecret, in.Code) {
			return nil, core.ErrTOTPInvalid
		}
		state.Verified = true
		if err := s.deps.TOTPStore.Put(ctx, proof.UserID, state); err != nil {
			return nil, err
		}
		s.logInfo("two_factor_enabled", "user_id", proof.UserID)
		audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.TwoFactorEnabled, UserID: proof.UserID, Outcome: "success"})
	} else if !s.codeMatches(plainSecret, in.Code) {
		digest := secret.Digest(in.Code)
		idx := -1
		for i, candidate := range state.BackupCodes {
			if subtleCompare(candidate, digest) {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, core.ErrTOTPInvalid
		}
		state.BackupCodes = append(state.BackupCodes[:idx], state.BackupCodes[idx+1:]...)
		if err := s.deps.TOTPStore.Put(ctx, proof.UserID, state); err != nil {
			return nil, err
		}
		s.logInfo("backup_code_used", "user_id", proof.UserID)
		audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.BackupCodeUsed, UserID: proof.UserID, Outcome: "success"})
	}
	if _, err := s.deps.Tokens.Consume(ctx, core.TokenTwoFactor, in.Challenge); err != nil {
		return nil, err
	}
	method := core.SignInMethodPassword
	if embedded, parseErr := token.ParseData(in.Challenge); parseErr == nil && embedded != "" {
		method = embedded
	}
	user, err := s.deps.Store.UserByID(ctx, proof.UserID)
	if err != nil {
		return nil, err
	}
	sessionToken, err := s.deps.CreateSession(ctx, user.ID, in.UserAgent)
	if err != nil {
		return nil, err
	}
	return &core.SignInResult{User: user, SessionToken: sessionToken, LastSignInMethod: method}, nil
}

// DisableTwoFactor removes a User's enrollment after a password check.
func (s *Service) DisableTwoFactor(ctx context.Context, in core.DisableTwoFactorInput) error {
	if err := s.requireTOTP(); err != nil {
		return err
	}
	if err := s.allow(ctx, "disable-two-factor", in.RateLimitKey); err != nil {
		return err
	}
	userID := in.UserID
	if userID == "" {
		return core.ErrInvalidCredentials
	}
	if err := s.verifyPassword(ctx, userID, in.Password); err != nil {
		return err
	}
	if err := s.deps.TOTPStore.Delete(ctx, userID); err != nil {
		return err
	}
	s.logInfo("two_factor_disabled", "user_id", userID)
	audit.Emit(ctx, s.deps.AuditSink, s.deps.Logger, core.AuditEvent{Name: audit.TwoFactorDisabled, UserID: userID, Outcome: "success"})
	return nil
}

// RegenerateBackupCodes replaces all Backup codes after a password check.
func (s *Service) RegenerateBackupCodes(ctx context.Context, in core.RegenerateBackupCodesInput) (*core.RegenerateBackupCodesResult, error) {
	if err := s.requireTOTP(); err != nil {
		return nil, err
	}
	if err := s.allow(ctx, "regenerate-backup-codes", in.RateLimitKey); err != nil {
		return nil, err
	}
	userID := in.UserID
	if userID == "" {
		return nil, core.ErrInvalidCredentials
	}
	if err := s.verifyPassword(ctx, userID, in.Password); err != nil {
		return nil, err
	}
	fresh, err := s.deps.IsSessionFresh(ctx, in.SessionToken, s.deps.FreshWindow)
	if err != nil || !fresh {
		return nil, core.ErrSessionNotFresh
	}
	state, err := s.deps.TOTPStore.Get(ctx, userID)
	if err != nil || !state.Verified {
		return nil, core.ErrTOTPNotEnabled
	}
	codes, digests, err := s.newBackupCodes()
	if err != nil {
		return nil, err
	}
	state.BackupCodes = digests
	if err := s.deps.TOTPStore.Put(ctx, userID, state); err != nil {
		return nil, err
	}
	s.logInfo("backup_codes_regenerated", "user_id", userID)
	return &core.RegenerateBackupCodesResult{BackupCodes: codes}, nil
}
