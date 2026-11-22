package csrf

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"testing"
	"time"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

func TestKeyRingSignsWithFirstAndVerifiesAll(t *testing.T) {
	first := []byte("first-key-12345678901234567890123")
	second := []byte("second-key-1234567890123456789012")
	clock := fixedClock{at: time.Now()}
	guard := New([][]byte{first, second}, clock, "csrf", "session", "/", "", true, http.SameSiteLaxMode, "", map[string]bool{}, false, nil)
	token, err := guard.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !guard.Valid(token) {
		t.Fatal("token signed with first key should verify")
	}

	payload := "abc." + strconv.FormatInt(clock.Now().Add(time.Hour).Unix(), 10)
	mac := hmac.New(sha256.New, second)
	_, _ = mac.Write([]byte(payload))
	older := payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !guard.Valid(older) {
		t.Fatal("token signed with a ring key should verify")
	}

	mac = hmac.New(sha256.New, []byte("unknown-key-12345678901234567890"))
	_, _ = mac.Write([]byte(payload))
	foreign := payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if guard.Valid(foreign) {
		t.Fatal("token signed outside the ring must be rejected")
	}
}
