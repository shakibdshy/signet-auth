package console_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/shakibdshy/signet"
	"github.com/shakibdshy/signet/mailer/console"
)

func TestMailerWritesMessage(t *testing.T) {
	var out bytes.Buffer
	var m signet.Mailer = console.New(&out)
	err := m.Send(context.Background(), signet.Message{
		To: "user@example.com", Subject: "Verify your email",
		TextBody: "plain body", HTMLBody: "<p>html body</p>",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	for _, want := range []string{"user@example.com", "Verify your email", "plain body", "<p>html body</p>"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output = %q, want %q", out.String(), want)
		}
	}
}
