// Package smtp provides a Mailer adapter that delivers messages through an
// SMTP server. Transport security is required unless explicitly disabled.
package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"

	"github.com/shakibdshy/signet"
)

// TLSMode selects how the SMTP connection is secured.
type TLSMode string

const (
	// StartTLS upgrades a plain connection using STARTTLS.
	StartTLS TLSMode = "starttls"
	// ImplicitTLS wraps the connection in TLS from the start.
	ImplicitTLS TLSMode = "implicit"
	// InsecurePlaintext disables transport security.
	InsecurePlaintext TLSMode = "plaintext"
)

// Config configures an SMTP Mailer.
type Config struct {
	Host                   string
	Port                   string
	Username               string
	Password               string
	From                   string
	TLS                    TLSMode
	InsecureAllowPlaintext bool
}

// Mailer delivers messages through an SMTP server.
type Mailer struct {
	cfg Config
}

// New validates cfg and returns an SMTP Mailer.
func New(cfg Config) (*Mailer, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, errors.New("signet/smtp: Host is required")
	}
	if strings.TrimSpace(cfg.From) == "" {
		return nil, errors.New("signet/smtp: From is required")
	}
	if cfg.TLS == "" {
		cfg.TLS = StartTLS
	}
	switch cfg.TLS {
	case StartTLS, ImplicitTLS:
	case InsecurePlaintext:
		if !cfg.InsecureAllowPlaintext {
			return nil, errors.New("signet/smtp: plaintext transport requires InsecureAllowPlaintext")
		}
		slog.Warn("signet/smtp: insecure plaintext transport enabled", "setting", "InsecureAllowPlaintext")
	default:
		return nil, errors.New("signet/smtp: unknown TLS mode")
	}
	if cfg.Port == "" {
		switch cfg.TLS {
		case ImplicitTLS:
			cfg.Port = "465"
		case InsecurePlaintext:
			cfg.Port = "25"
		default:
			cfg.Port = "587"
		}
	}
	return &Mailer{cfg: cfg}, nil
}

// Send delivers msg to its recipient.
func (m *Mailer) Send(ctx context.Context, msg signet.Message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	address := net.JoinHostPort(m.cfg.Host, m.cfg.Port)
	var client *smtp.Client
	if m.cfg.TLS == ImplicitTLS {
		conn, err := tls.Dial("tcp", address, &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12})
		if err != nil {
			return fmt.Errorf("signet/smtp: dial: %w", err)
		}
		client, err = smtp.NewClient(conn, m.cfg.Host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("signet/smtp: client: %w", err)
		}
	} else {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			return fmt.Errorf("signet/smtp: dial: %w", err)
		}
		client, err = smtp.NewClient(conn, m.cfg.Host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("signet/smtp: client: %w", err)
		}
		if m.cfg.TLS == StartTLS {
			if err := client.StartTLS(&tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
				_ = client.Close()
				return fmt.Errorf("signet/smtp: starttls: %w", err)
			}
		}
	}
	defer func() { _ = client.Close() }()

	if m.cfg.Username != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("signet/smtp: auth: %w", err)
		}
	}
	if err := client.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("signet/smtp: sender: %w", err)
	}
	if err := client.Rcpt(msg.To); err != nil {
		return fmt.Errorf("signet/smtp: recipient: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("signet/smtp: data: %w", err)
	}
	var alternative bytes.Buffer
	multipartWriter := multipart.NewWriter(&alternative)
	textPart, err := multipartWriter.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=UTF-8"}})
	if err != nil {
		_ = writer.Close()
		return fmt.Errorf("signet/smtp: text part: %w", err)
	}
	if _, err := textPart.Write([]byte(msg.TextBody)); err != nil {
		_ = writer.Close()
		return fmt.Errorf("signet/smtp: text body: %w", err)
	}
	htmlPart, err := multipartWriter.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/html; charset=UTF-8"}})
	if err != nil {
		_ = writer.Close()
		return fmt.Errorf("signet/smtp: html part: %w", err)
	}
	if _, err := htmlPart.Write([]byte(msg.HTMLBody)); err != nil {
		_ = writer.Close()
		return fmt.Errorf("signet/smtp: html body: %w", err)
	}
	if err := multipartWriter.Close(); err != nil {
		_ = writer.Close()
		return fmt.Errorf("signet/smtp: multipart: %w", err)
	}
	body := fmt.Sprintf("To: %s\r\nSubject: %s\r\nContent-Type: multipart/alternative; boundary=%q\r\n\r\n%s",
		msg.To, msg.Subject, multipartWriter.Boundary(), alternative.String())
	if _, err := writer.Write([]byte(body)); err != nil {
		_ = writer.Close()
		return fmt.Errorf("signet/smtp: write: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("signet/smtp: close data: %w", err)
	}
	return client.Quit()
}
