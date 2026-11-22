package tests

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/internal/testutil"
)

type fakeTOTPStore struct {
	mu     sync.Mutex
	states map[string]*signet.TOTPState
}

func newFakeTOTPStore() *fakeTOTPStore {
	return &fakeTOTPStore{states: make(map[string]*signet.TOTPState)}
}

func (s *fakeTOTPStore) Get(_ context.Context, userID string) (*signet.TOTPState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.states[userID]
	if !ok {
		return nil, signet.ErrNotFound
	}
	copy := *state
	copy.BackupCodes = append([]string(nil), state.BackupCodes...)
	return &copy, nil
}

func (s *fakeTOTPStore) Put(_ context.Context, userID string, state *signet.TOTPState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := *state
	copy.BackupCodes = append([]string(nil), state.BackupCodes...)
	s.states[userID] = &copy
	return nil
}

func (s *fakeTOTPStore) Delete(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, userID)
	return nil
}

func twoFactorClient(t *testing.T, configure func(*signet.Config)) (*signet.Client, *testutil.Store, *fakeTOTPStore, string) {
	t.Helper()
	store := testutil.NewStore()
	totpStore := newFakeTOTPStore()
	cfg := testutil.NewConfig()
	cfg.Store = store
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	cfg.TOTPStore = totpStore
	cfg.TOTPKey = []byte("0123456789abcdef0123456789abcdef")
	cfg.JWT = &signet.JWTConfig{Algorithm: "HS256", Key: []byte("jwt-key-123456789012345678901234")}
	if configure != nil {
		configure(&cfg)
	}
	client, err := signet.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	signUp, err := client.SignUp(context.Background(), signet.SignUpInput{
		Email: "user@example.com", Password: "correct horse",
	})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	return client, store, totpStore, signUp.User.ID
}

func totpCode(t *testing.T, uri string, at time.Time) string {
	t.Helper()
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse URI: %v", err)
	}
	secret := parsed.Query().Get("secret")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	counter := uint64(at.Unix() / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

func enableFactor(t *testing.T, client *signet.Client, userID string) *signet.EnableTwoFactorResult {
	t.Helper()
	result, err := client.EnableTwoFactor(context.Background(), signet.EnableTwoFactorInput{UserID: userID, Password: "correct horse"})
	if err != nil {
		t.Fatalf("EnableTwoFactor: %v", err)
	}
	if len(result.BackupCodes) != 10 {
		t.Fatalf("backup codes = %+v, want 10", result.BackupCodes)
	}
	return result
}

func TestTwoFactorEnableRequiresConfirmation(t *testing.T) {
	client, _, totpStore, userID := twoFactorClient(t, nil)
	ctx := context.Background()
	enableFactor(t, client, userID)
	state, err := totpStore.Get(ctx, userID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if state.Verified {
		t.Fatal("enrollment must stay pending until a code is verified")
	}
	if _, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"}); err != nil {
		t.Fatalf("sign-in before confirmation: %v", err)
	}
}

func TestTwoFactorChallengeAndVerification(t *testing.T) {
	clock := &testutil.Clock{At: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	client, _, _, userID := twoFactorClient(t, func(cfg *signet.Config) { cfg.Clock = clock })
	ctx := context.Background()
	enabled := enableFactor(t, client, userID)
	code := totpCode(t, enabled.TOTPURI, clock.At)
	if _, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{Challenge: "not-a-challenge", Code: code}); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatalf("invalid challenge error = %v", err)
	}

	// Confirm enrollment through a challenge issued for a fresh sign-in.
	first, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if _, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{Challenge: first.TwoFactorChallenge, Code: code}); err != nil {
		t.Fatalf("VerifyTwoFactor: %v", err)
	}

	second, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("second SignIn: %v", err)
	}
	if second.SessionToken != "" || second.TwoFactorChallenge == "" {
		t.Fatalf("enrolled sign-in should return a challenge: %+v", second)
	}
	if _, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{Challenge: second.TwoFactorChallenge, Code: totpCode(t, enabled.TOTPURI, clock.At)}); err != nil {
		t.Fatalf("second VerifyTwoFactor: %v", err)
	}
	if _, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{Challenge: second.TwoFactorChallenge, Code: code}); !errors.Is(err, signet.ErrTokenInvalid) {
		t.Fatal("challenge replay should fail")
	}
}

func TestTwoFactorBackupCodesAreSingleUse(t *testing.T) {
	clock := &testutil.Clock{At: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	client, _, _, userID := twoFactorClient(t, func(cfg *signet.Config) { cfg.Clock = clock })
	ctx := context.Background()
	enabled := enableFactor(t, client, userID)
	first, _ := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if _, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{Challenge: first.TwoFactorChallenge, Code: totpCode(t, enabled.TOTPURI, clock.At)}); err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	backup := enabled.BackupCodes[0]
	challenge, _ := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if _, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{Challenge: challenge.TwoFactorChallenge, Code: backup}); err != nil {
		t.Fatalf("backup code: %v", err)
	}
	replay, _ := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if _, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{Challenge: replay.TwoFactorChallenge, Code: backup}); !errors.Is(err, signet.ErrTOTPInvalid) {
		t.Fatalf("replayed backup code error = %v", err)
	}
	fresh, err := client.RegenerateBackupCodes(ctx, signet.RegenerateBackupCodesInput{UserID: userID, Password: "correct horse"})
	if err != nil {
		t.Fatalf("RegenerateBackupCodes: %v", err)
	}
	if len(fresh.BackupCodes) != 10 || fresh.BackupCodes[0] == backup {
		t.Fatalf("regenerated codes = %+v", fresh.BackupCodes)
	}
}

func TestTwoFactorWrongCodeAndDisable(t *testing.T) {
	clock := &testutil.Clock{At: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	client, _, _, userID := twoFactorClient(t, func(cfg *signet.Config) { cfg.Clock = clock })
	ctx := context.Background()
	enabled := enableFactor(t, client, userID)
	first, _ := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if _, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{Challenge: first.TwoFactorChallenge, Code: totpCode(t, enabled.TOTPURI, clock.At)}); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	challenge, _ := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if _, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{Challenge: challenge.TwoFactorChallenge, Code: "000000"}); !errors.Is(err, signet.ErrTOTPInvalid) {
		t.Fatalf("wrong code error = %v", err)
	}
	if err := client.DisableTwoFactor(ctx, signet.DisableTwoFactorInput{UserID: userID, Password: "wrong password"}); !errors.Is(err, signet.ErrInvalidCredentials) {
		t.Fatalf("disable with wrong password = %v", err)
	}
	if err := client.DisableTwoFactor(ctx, signet.DisableTwoFactorInput{UserID: userID, Password: "correct horse"}); err != nil {
		t.Fatalf("DisableTwoFactor: %v", err)
	}
	result, err := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil || result.SessionToken == "" || result.TwoFactorChallenge != "" {
		t.Fatalf("sign-in after disable = %+v, %v", result, err)
	}
}

func TestJWTTokenExchangeRequiresSecondFactor(t *testing.T) {
	clock := &testutil.Clock{At: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	client, _, _, userID := twoFactorClient(t, func(cfg *signet.Config) { cfg.Clock = clock })
	ctx := context.Background()
	enabled := enableFactor(t, client, userID)
	first, _ := client.SignIn(ctx, signet.SignInInput{Email: "user@example.com", Password: "correct horse"})
	if _, err := client.VerifyTwoFactor(ctx, signet.VerifyTwoFactorInput{Challenge: first.TwoFactorChallenge, Code: totpCode(t, enabled.TOTPURI, clock.At)}); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	pair, err := client.ExchangeToken(ctx, signet.TokenInput{Email: "user@example.com", Password: "correct horse"})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if pair.AccessToken != "" || pair.TwoFactorChallenge == "" {
		t.Fatalf("expected challenge only: %+v", pair)
	}
	final, err := client.ExchangeToken(ctx, signet.TokenInput{
		Challenge: pair.TwoFactorChallenge, Code: totpCode(t, enabled.TOTPURI, clock.At),
	})
	if err != nil || final.AccessToken == "" {
		t.Fatalf("token exchange with second factor = %+v, %v", final, err)
	}
}

func TestTwoFactorRequiresStoreAndKey(t *testing.T) {
	cfg := testutil.NewConfig()
	cfg.Store = testutil.NewStore()
	cfg.Mailer = testutil.NewMailer()
	cfg.RateLimiter = &testutil.Limiter{Allowed: true}
	if _, err := signet.New(cfg); err != nil {
		t.Fatalf("New without TOTP store should succeed: %v", err)
	}
	cfg.TOTPStore = newFakeTOTPStore()
	if _, err := signet.New(cfg); !errors.Is(err, signet.ErrTOTPNotConfigured) {
		t.Fatalf("missing key error = %v", err)
	}
}
