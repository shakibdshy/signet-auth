package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/shakibdshy/signet"
)

func TestDefaultTemplatesRenderBothBodies(t *testing.T) {
	data := signet.TemplateData{
		Email:     "user@example.com",
		Name:      "Ada",
		URL:       "https://app.example.com/verify?token=abc",
		ExpiresAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}
	for name, render := range map[string]func(signet.TemplateData) signet.Message{
		"verify":  signet.DefaultTemplates.VerifyEmail,
		"reset":   signet.DefaultTemplates.ResetPassword,
		"changed": signet.DefaultTemplates.PasswordChanged,
	} {
		t.Run(name, func(t *testing.T) {
			msg := render(data)
			if msg.To != data.Email || msg.Subject == "" {
				t.Errorf("message = %+v, want recipient and subject", msg)
			}
			if name != "changed" && (!strings.Contains(msg.TextBody, data.URL) || !strings.Contains(msg.HTMLBody, data.URL)) {
				t.Errorf("bodies = %q / %q, want the link in both", msg.TextBody, msg.HTMLBody)
			}
			if !strings.Contains(msg.HTMLBody, "<") {
				t.Errorf("HTML body = %q, want markup", msg.HTMLBody)
			}
		})
	}
}
