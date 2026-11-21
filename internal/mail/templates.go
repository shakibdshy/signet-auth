// Package mail renders Signet's transactional email templates.
package mail

import (
	"bytes"
	htmltemplate "html/template"
	"io"
	texttemplate "text/template"

	"github.com/shakibdshy/signet/internal/core"
)

type defaultTemplates struct {
	changeHTML  *htmltemplate.Template
	changeText  *texttemplate.Template
	verifyHTML  *htmltemplate.Template
	verifyText  *texttemplate.Template
	resetHTML   *htmltemplate.Template
	resetText   *texttemplate.Template
	changedHTML *htmltemplate.Template
	changedText *texttemplate.Template
}

// DefaultTemplates is the built-in email template set. HTML is rendered with
// html/template and the plain-text alternative with text/template.
var DefaultTemplates core.EmailTemplates = newDefaultTemplates()

func newDefaultTemplates() *defaultTemplates {
	return &defaultTemplates{
		verifyHTML:  htmltemplate.Must(htmltemplate.New("verify").Parse(`<p>Hello {{.Name}},</p><p><a href="{{.URL}}">Verify your email address</a></p><p>This link expires {{.ExpiresAt}}.</p>`)),
		verifyText:  texttemplate.Must(texttemplate.New("verify").Parse("Hello {{.Name}},\n\nVerify your email address:\n{{.URL}}\n\nThis link expires {{.ExpiresAt}}.\n")),
		resetHTML:   htmltemplate.Must(htmltemplate.New("reset").Parse(`<p>Hello {{.Name}},</p><p><a href="{{.URL}}">Reset your password</a></p><p>This link expires {{.ExpiresAt}}. If you did not request this, ignore the message.</p>`)),
		resetText:   texttemplate.Must(texttemplate.New("reset").Parse("Hello {{.Name}},\n\nReset your password:\n{{.URL}}\n\nThis link expires {{.ExpiresAt}}. If you did not request this, ignore this message.\n")),
		changeHTML:  htmltemplate.Must(htmltemplate.New("change").Parse(`<p>Hello {{.Name}},</p><p>Confirm your new email address:</p><p><a href="{{.URL}}">{{.URL}}</a></p><p>This link expires {{.ExpiresAt}}.</p>`)),
		changeText:  texttemplate.Must(texttemplate.New("change").Parse("Hello {{.Name}},\n\nConfirm your new email address:\n{{.URL}}\n\nThis link expires {{.ExpiresAt}}.\n")),
		changedHTML: htmltemplate.Must(htmltemplate.New("changed").Parse(`<p>Hello {{.Name}},</p><p>Your password was changed. If you did not do this, contact support.</p>`)),
		changedText: texttemplate.Must(texttemplate.New("changed").Parse("Hello {{.Name}},\n\nYour password was changed. If you did not do this, contact support.\n")),
	}
}

func (d *defaultTemplates) VerifyEmail(data core.TemplateData) core.Message {
	return core.Message{
		To: data.Email, Subject: "Verify your email",
		TextBody: render(d.verifyText, data), HTMLBody: render(d.verifyHTML, data),
	}
}

func (d *defaultTemplates) ResetPassword(data core.TemplateData) core.Message {
	return core.Message{
		To: data.Email, Subject: "Reset your password",
		TextBody: render(d.resetText, data), HTMLBody: render(d.resetHTML, data),
	}
}

func (d *defaultTemplates) PasswordChanged(data core.TemplateData) core.Message {
	return core.Message{
		To: data.Email, Subject: "Your password was changed",
		TextBody: render(d.changedText, data), HTMLBody: render(d.changedHTML, data),
	}
}

type executableTemplate interface {
	Execute(io.Writer, any) error
}

func render(t executableTemplate, data core.TemplateData) string {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return ""
	}
	return buf.String()
}

func (d *defaultTemplates) ChangeEmail(data core.TemplateData) core.Message {
	return core.Message{
		To: data.Email, Subject: "Verify your email change",
		TextBody: render(d.changeText, data), HTMLBody: render(d.changeHTML, data),
	}
}
