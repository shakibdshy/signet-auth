package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/mail"
)

func TestConsumedTokenStillMatchesInvalidToken(t *testing.T) {
	if !errors.Is(core.ErrTokenConsumed, core.ErrTokenInvalid) {
		t.Fatal("ErrTokenConsumed must wrap ErrTokenInvalid for existing callers")
	}
}

func TestNewOTPIsSixDigits(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 500; i++ {
		code, err := newOTP()
		if err != nil {
			t.Fatalf("newOTP: %v", err)
		}
		if len(code) != 6 {
			t.Fatalf("code %q is not six digits", code)
		}
		for _, char := range code {
			if char < '0' || char > '9' {
				t.Fatalf("code %q contains a non-digit", code)
			}
		}
		seen[code] = true
	}
	if len(seen) < 400 {
		t.Fatalf("only %d distinct codes in 500 draws; generator looks biased", len(seen))
	}
}

func TestRedirectAllowedUsesExactAllowlists(t *testing.T) {
	service := &VerificationService{deps: VerificationDependencies{
		AppURL: "https://app.example.com",
		Passwordless: &core.PasswordlessConfig{
			AllowedRedirects: []string{"https://app.example.com/welcome"},
		},
		OAuthRedirects: []string{"https://oauth.example.com/callback"},
	}}
	for _, redirect := range []string{
		"https://app.example.com/welcome",
		"https://oauth.example.com/callback",
		"https://app.example.com",
	} {
		if !service.redirectAllowed(redirect) {
			t.Errorf("redirect %q should be allowed", redirect)
		}
	}
	for _, redirect := range []string{
		"",
		"https://app.example.com/attacker",
		"https://evil.example.com/welcome",
	} {
		if service.redirectAllowed(redirect) {
			t.Errorf("redirect %q should be rejected", redirect)
		}
	}
}

func TestDefaultPasswordlessTemplatesRenderBothBodies(t *testing.T) {
	data := core.TemplateData{
		Email: "user@example.com", Name: "Ada",
		URL: "https://app.example.com/auth/verify-magic-link?token=x", Code: "123456",
	}
	link := mail.MagicLinkMessage(data)
	otp := mail.EmailOTPMessage(data)
	for name, tc := range map[string]struct {
		message core.Message
		want    string
	}{
		"magic link": {link, data.URL},
		"otp":        {otp, data.Code},
	} {
		if tc.message.To != data.Email || tc.message.Subject == "" {
			t.Errorf("%s: message = %+v", name, tc.message)
		}
		if !strings.Contains(tc.message.TextBody, tc.want) || !strings.Contains(tc.message.HTMLBody, tc.want) {
			t.Errorf("%s: bodies do not render %q: %+v", name, tc.want, tc.message)
		}
	}
}
