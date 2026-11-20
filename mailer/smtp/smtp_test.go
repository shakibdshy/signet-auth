package smtp_test

import (
	"testing"

	"github.com/shakibdshy/signet/mailer/smtp"
)

func TestNewValidatesConfiguration(t *testing.T) {
	tests := []struct {
		name string
		cfg  smtp.Config
	}{
		{"missing host", smtp.Config{From: "noreply@example.com"}},
		{"missing from", smtp.Config{Host: "smtp.example.com"}},
		{"plaintext without opt-in", smtp.Config{Host: "smtp.example.com", From: "noreply@example.com", TLS: smtp.InsecurePlaintext}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := smtp.New(tt.cfg); err == nil {
				t.Fatalf("New(%s) error = nil, want validation error", tt.name)
			}
		})
	}
}

func TestNewAcceptsTLSModes(t *testing.T) {
	base := smtp.Config{Host: "smtp.example.com", Port: "587", From: "noreply@example.com"}
	for name, cfg := range map[string]smtp.Config{
		"starttls default": base,
		"implicit tls":     func() smtp.Config { c := base; c.TLS = smtp.ImplicitTLS; c.Port = "465"; return c }(),
		"explicit plaintext": func() smtp.Config {
			c := base
			c.TLS = smtp.InsecurePlaintext
			c.InsecureAllowPlaintext = true
			return c
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := smtp.New(cfg); err != nil {
				t.Fatalf("New(%s) error = %v", name, err)
			}
		})
	}
}
