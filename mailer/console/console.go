// Package console provides a development Mailer that writes messages to an
// io.Writer. It prints links and must not be used in production.
package console

import (
	"context"
	"fmt"
	"io"

	"github.com/shakibdshy/signet-auth"
)

// Mailer writes messages to a writer instead of delivering them.
type Mailer struct {
	out io.Writer
}

// New returns a Mailer that writes to out. It is intended for local
// development: verification and reset links appear in the output.
func New(out io.Writer) *Mailer {
	return &Mailer{out: out}
}

// Send writes the message to the configured writer.
func (m *Mailer) Send(_ context.Context, msg signet.Message) error {
	_, err := fmt.Fprintf(m.out, "To: %s\nSubject: %s\n\n%s\n\n%s\n",
		msg.To, msg.Subject, msg.TextBody, msg.HTMLBody)
	return err
}
