package signet

import (
	"github.com/shakibdshy/signet/internal/core"
	"github.com/shakibdshy/signet/internal/mail"
)

// TemplateData is the information available to an email template.
type TemplateData = core.TemplateData

// EmailTemplates renders the transactional email Signet sends.
type EmailTemplates = core.EmailTemplates

// DefaultTemplates is the built-in email template set.
var DefaultTemplates = mail.DefaultTemplates
