package signet

import "github.com/shakibdshy/signet/internal/core"

// Message is the email Signet asks a Mailer to deliver.
type Message = core.Message

// Mailer delivers transactional email such as verification and password
// reset messages.
type Mailer = core.Mailer
