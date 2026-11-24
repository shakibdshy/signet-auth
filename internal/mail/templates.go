// Package mail renders Signet's transactional email templates.
package mail

import (
	"bytes"
	htmltemplate "html/template"
	"io"
	texttemplate "text/template"

	"github.com/shakibdshy/signet-auth/internal/core"
)

type defaultTemplates struct {
	deleteHTML  *htmltemplate.Template
	deleteText  *texttemplate.Template
	changeHTML  *htmltemplate.Template
	changeText  *texttemplate.Template
	verifyHTML  *htmltemplate.Template
	verifyText  *texttemplate.Template
	resetHTML   *htmltemplate.Template
	resetText   *texttemplate.Template
	changedHTML *htmltemplate.Template
	changedText *texttemplate.Template
	magicHTML   *htmltemplate.Template
	magicText   *texttemplate.Template
	otpHTML     *htmltemplate.Template
	otpText     *texttemplate.Template
}

var defaults = newDefaultTemplates()

// DefaultTemplates is the built-in email template set. HTML is rendered with
// html/template and the plain-text alternative with text/template.
var DefaultTemplates core.EmailTemplates = defaults

func newDefaultTemplates() *defaultTemplates {
	return &defaultTemplates{
		verifyHTML:  htmltemplate.Must(htmltemplate.New("verify").Parse(`<p>Hello {{.Name}},</p><p><a href="{{.URL}}">Verify your email address</a></p><p>This link expires {{.ExpiresAt}}.</p>`)),
		verifyText:  texttemplate.Must(texttemplate.New("verify").Parse("Hello {{.Name}},\n\nVerify your email address:\n{{.URL}}\n\nThis link expires {{.ExpiresAt}}.\n")),
		resetHTML:   htmltemplate.Must(htmltemplate.New("reset").Parse(`<p>Hello {{.Name}},</p><p><a href="{{.URL}}">Reset your password</a></p><p>This link expires {{.ExpiresAt}}. If you did not request this, ignore the message.</p>`)),
		resetText:   texttemplate.Must(texttemplate.New("reset").Parse("Hello {{.Name}},\n\nReset your password:\n{{.URL}}\n\nThis link expires {{.ExpiresAt}}. If you did not request this, ignore this message.\n")),
		deleteHTML:  htmltemplate.Must(htmltemplate.New("delete").Parse(`<p>Hello {{.Name}},</p><p>Confirm deletion of your account:</p><p><a href="{{.URL}}">{{.URL}}</a></p><p>This link expires {{.ExpiresAt}}.</p>`)),
		deleteText:  texttemplate.Must(texttemplate.New("delete").Parse("Hello {{.Name}},\n\nConfirm deletion of your account:\n{{.URL}}\n\nThis link expires {{.ExpiresAt}}.\n")),
		changeHTML:  htmltemplate.Must(htmltemplate.New("change").Parse(`<p>Hello {{.Name}},</p><p>Confirm your new email address:</p><p><a href="{{.URL}}">{{.URL}}</a></p><p>This link expires {{.ExpiresAt}}.</p>`)),
		changeText:  texttemplate.Must(texttemplate.New("change").Parse("Hello {{.Name}},\n\nConfirm your new email address:\n{{.URL}}\n\nThis link expires {{.ExpiresAt}}.\n")),
		changedHTML: htmltemplate.Must(htmltemplate.New("changed").Parse(`<p>Hello {{.Name}},</p><p>Your password was changed. If you did not do this, contact support.</p>`)),
		changedText: texttemplate.Must(texttemplate.New("changed").Parse("Hello {{.Name}},\n\nYour password was changed. If you did not do this, contact support.\n")),
		magicHTML:   htmltemplate.Must(htmltemplate.New("magic").Parse(`<p>Hello {{.Name}},</p><p><a href="{{.URL}}">Sign in</a></p><p>This link expires {{.ExpiresAt}}. If you did not request it, ignore the message.</p>`)),
		magicText:   texttemplate.Must(texttemplate.New("magic").Parse("Hello {{.Name}},\n\nSign in with this link:\n{{.URL}}\n\nThis link expires {{.ExpiresAt}}. If you did not request it, ignore this message.\n")),
		otpHTML:     htmltemplate.Must(htmltemplate.New("otp").Parse(`<p>Hello {{.Name}},</p><p>Your sign-in code is <strong>{{.Code}}</strong>.</p><p>This code expires {{.ExpiresAt}}. If you did not request it, ignore the message.</p>`)),
		otpText:     texttemplate.Must(texttemplate.New("otp").Parse("Hello {{.Name}},\n\nYour sign-in code is {{.Code}}.\n\nThis code expires {{.ExpiresAt}}. If you did not request it, ignore this message.\n")),
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

func (d *defaultTemplates) DeleteUser(data core.TemplateData) core.Message {
	return core.Message{
		To: data.Email, Subject: "Confirm account deletion",
		TextBody: render(d.deleteText, data), HTMLBody: render(d.deleteHTML, data),
	}
}

// MagicLinkMessage renders the built-in magic-link email. Custom template
// sets that do not implement MagicLinkTemplates still get this message.
func MagicLinkMessage(data core.TemplateData) core.Message {
	return core.Message{
		To: data.Email, Subject: "Sign in with a magic link",
		TextBody: render(defaults.magicText, data), HTMLBody: render(defaults.magicHTML, data),
	}
}

// EmailOTPMessage renders the built-in one-time code email. Custom template
// sets that do not implement EmailOTPTemplates still get this message.
func EmailOTPMessage(data core.TemplateData) core.Message {
	return core.Message{
		To: data.Email, Subject: "Your sign-in code",
		TextBody: render(defaults.otpText, data), HTMLBody: render(defaults.otpHTML, data),
	}
}

// MagicLink renders the passwordless magic-link email.
func (d *defaultTemplates) MagicLink(data core.TemplateData) core.Message {
	return MagicLinkMessage(data)
}

// EmailOTP renders the passwordless one-time code email.
func (d *defaultTemplates) EmailOTP(data core.TemplateData) core.Message {
	return EmailOTPMessage(data)
}
