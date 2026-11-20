package signet

import "context"

// Message is the email Signet asks a Mailer to deliver.
type Message struct {
	To       string
	Subject  string
	TextBody string
	HTMLBody string
}

// Mailer delivers transactional email such as verification and password
// reset messages.
type Mailer interface {
	// Send delivers a Message to its recipient.
	Send(context.Context, Message) error
}
