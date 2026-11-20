package signet

import (
	"bytes"
	htmltemplate "html/template"
	"io"
	texttemplate "text/template"

	"github.com/shakibdshy/signet/internal/core"
)

// TemplateData is the information available to an email template.
type TemplateData = core.TemplateData

// EmailTemplates renders the transactional email Signet sends. Applications
// can replace the defaults by setting Config.Templates.
type EmailTemplates = core.EmailTemplates

type defaultTemplates struct {
	verifyHTML  *htmltemplate.Template
	verifyText  *texttemplate.Template
	resetHTML   *htmltemplate.Template
	resetText   *texttemplate.Template
	changedHTML *htmltemplate.Template
	changedText *texttemplate.Template
}

// DefaultTemplates is the built-in email template set. HTML is rendered with
// html/template and the plain-text alternative with text/template.
var DefaultTemplates EmailTemplates = newDefaultTemplates()

func newDefaultTemplates() *defaultTemplates {
	return &defaultTemplates{
		verifyHTML:  htmltemplate.Must(htmltemplate.New("verify").Parse(`<p>Hello {{.Name}},</p><p><a href="{{.URL}}">Verify your email address</a></p><p>This link expires {{.ExpiresAt}}.</p>`)),
		verifyText:  texttemplate.Must(texttemplate.New("verify").Parse("Hello {{.Name}},\n\nVerify your email address:\n{{.URL}}\n\nThis link expires {{.ExpiresAt}}.\n")),
		resetHTML:   htmltemplate.Must(htmltemplate.New("reset").Parse(`<p>Hello {{.Name}},</p><p><a href="{{.URL}}">Reset your password</a></p><p>This link expires {{.ExpiresAt}}. If you did not request this, ignore the message.</p>`)),
		resetText:   texttemplate.Must(texttemplate.New("reset").Parse("Hello {{.Name}},\n\nReset your password:\n{{.URL}}\n\nThis link expires {{.ExpiresAt}}. If you did not request this, ignore this message.\n")),
		changedHTML: htmltemplate.Must(htmltemplate.New("changed").Parse(`<p>Hello {{.Name}},</p><p>Your password was changed. If you did not do this, contact support.</p>`)),
		changedText: texttemplate.Must(texttemplate.New("changed").Parse("Hello {{.Name}},\n\nYour password was changed. If you did not do this, contact support.\n")),
	}
}

func (d *defaultTemplates) VerifyEmail(data TemplateData) Message {
	return Message{
		To: data.Email, Subject: "Verify your email",
		TextBody: render(d.verifyText, data), HTMLBody: render(d.verifyHTML, data),
	}
}

func (d *defaultTemplates) ResetPassword(data TemplateData) Message {
	return Message{
		To: data.Email, Subject: "Reset your password",
		TextBody: render(d.resetText, data), HTMLBody: render(d.resetHTML, data),
	}
}

func (d *defaultTemplates) PasswordChanged(data TemplateData) Message {
	return Message{
		To: data.Email, Subject: "Your password was changed",
		TextBody: render(d.changedText, data), HTMLBody: render(d.changedHTML, data),
	}
}

type executableTemplate interface {
	Execute(io.Writer, any) error
}

func render(t executableTemplate, data TemplateData) string {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return ""
	}
	return buf.String()
}
