package main

// Demo-only inbox mailer: a thread-safe bounded ring buffer that captures the
// emails Signet would deliver, exposed over GET /auth/demo/inbox so visitors
// can complete email-driven flows (verification, magic link, OTP, reset) in
// the browser without a real mail provider. Gated behind DEMO_MODE=true in
// main.go; never enabled in production.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shakibdshy/signet-auth"
)

// demoInboxCapacity bounds the ring buffer: the last N emails are kept and
// older ones are dropped, so memory usage stays constant.
const demoInboxCapacity = 50

var (
	// linkPattern matches the first URL in a plain-text email body; Signet
	// renders verification, reset and magic links on their own line.
	linkPattern = regexp.MustCompile(`https?://\S+`)
	// codePattern matches the six-digit OTP code in the sign-in-code email.
	codePattern = regexp.MustCompile(`\b\d{6}\b`)
)

// DemoMessage is one captured email as exposed by the demo inbox. Wire keys
// are snake_case.
type DemoMessage struct {
	ID        string `json:"id"`
	To        string `json:"to"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
	URL       string `json:"url"`
	Token     string `json:"token"`
	Code      string `json:"code"`
	CreatedAt string `json:"created_at"`
}

// DemoMemoryMailer is a signet.Mailer that keeps the last demoInboxCapacity
// messages in memory instead of delivering them. Safe for concurrent use.
type DemoMemoryMailer struct {
	mu    sync.RWMutex
	ring  []DemoMessage // fixed-capacity ring buffer
	head  int           // next write position
	count int           // messages currently stored, capped at len(ring)

	// now is swappable for deterministic timestamps in tests.
	now func() time.Time
}

// NewDemoMemoryMailer returns an empty demo inbox mailer.
func NewDemoMemoryMailer() *DemoMemoryMailer {
	return &DemoMemoryMailer{
		ring: make([]DemoMessage, demoInboxCapacity),
		now:  time.Now,
	}
}

// Send captures the message. It never fails in practice; a crypto/rand
// failure only degrades the generated ID.
func (m *DemoMemoryMailer) Send(_ context.Context, msg signet.Message) error {
	rec := DemoMessage{
		ID:        newDemoMessageID(),
		To:        msg.To,
		Subject:   msg.Subject,
		Body:      msg.TextBody,
		CreatedAt: m.now().UTC().Format(time.RFC3339),
	}
	rec.URL, rec.Token, rec.Code = extractDemoParts(msg.TextBody)

	m.mu.Lock()
	m.ring[m.head] = rec
	m.head = (m.head + 1) % len(m.ring)
	if m.count < len(m.ring) {
		m.count++
	}
	m.mu.Unlock()

	log.Printf("demo inbox: to=%s subject=%q url=%s code=%s", rec.To, rec.Subject, rec.URL, rec.Code)
	return nil
}

// Messages returns the stored messages for email, newest first. Matching is
// case-insensitive.
func (m *DemoMemoryMailer) Messages(email string) []DemoMessage {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Always non-nil so the endpoint renders "messages": [] when empty.
	out := make([]DemoMessage, 0, m.count)
	for i := 0; i < m.count; i++ {
		msg := m.ring[(m.head-1-i+len(m.ring))%len(m.ring)]
		if strings.EqualFold(msg.To, email) {
			out = append(out, msg)
		}
	}
	return out
}

// Handler returns the demo inbox endpoint: GET /auth/demo/inbox?email=...
// The email query parameter is required; without it nothing is exposed.
func (m *DemoMemoryMailer) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := strings.TrimSpace(r.URL.Query().Get("email"))
		if email == "" {
			writeJSONError(w, http.StatusBadRequest, "the email query parameter is required")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(struct {
			Messages []DemoMessage `json:"messages"`
		}{Messages: m.Messages(email)})
	})
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: message})
}

// extractDemoParts pulls the action URL, its token query parameter and a
// six-digit OTP code out of a plain-text email body. Anything absent stays
// empty.
func extractDemoParts(body string) (rawURL, token, code string) {
	if link := linkPattern.FindString(body); link != "" {
		rawURL = link
		if parsed, err := url.Parse(link); err == nil {
			token = parsed.Query().Get("token")
		}
	}
	if match := codePattern.FindString(body); match != "" {
		code = match
	}
	return rawURL, token, code
}

// newDemoMessageID returns a random opaque ID for a captured message.
func newDemoMessageID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// demoMode reports whether the demo inbox is enabled. DEMO_MODE=true swaps
// the console mailer for an in-memory one and exposes GET /auth/demo/inbox;
// it must never be set on a production deployment.
func demoMode() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("DEMO_MODE")), "true")
}
