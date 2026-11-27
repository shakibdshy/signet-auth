package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/shakibdshy/signet-auth"
)

var _ signet.Mailer = (*DemoMemoryMailer)(nil)

// newTestMailer returns a mailer whose clock advances one second per send, so
// created_at values (and therefore ordering) are deterministic. The closure
// serialises its counter because Send is safe for concurrent use.
func newTestMailer() *DemoMemoryMailer {
	m := NewDemoMemoryMailer()
	var mu sync.Mutex
	base := time.Date(2026, 11, 28, 1, 45, 0, 0, time.UTC)
	m.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		base = base.Add(time.Second)
		return base
	}
	return m
}

func TestDemoMemoryMailerRingCapacity(t *testing.T) {
	m := newTestMailer()
	for i := 1; i <= demoInboxCapacity+5; i++ {
		err := m.Send(context.Background(), signet.Message{
			To: "ada@example.com", Subject: "old test", TextBody: fmt.Sprintf("message %d", i),
		})
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	got := m.Messages("ada@example.com")
	if len(got) != demoInboxCapacity {
		t.Fatalf("got %d messages, want %d", len(got), demoInboxCapacity)
	}
	// Newest first: the first entry is the most recent send, the last entry is
	// the oldest survivor of the ring.
	if got[0].Body != fmt.Sprintf("message %d", demoInboxCapacity+5) {
		t.Fatalf("newest message = %q, want message %d", got[0].Body, demoInboxCapacity+5)
	}
	wantOldest := demoInboxCapacity + 5 - demoInboxCapacity + 1
	if got[len(got)-1].Body != fmt.Sprintf("message %d", wantOldest) {
		t.Fatalf("oldest message = %q, want message %d", got[len(got)-1].Body, wantOldest)
	}
	_, err := time.Parse(time.RFC3339, got[0].CreatedAt)
	if err != nil {
		t.Fatalf("created_at %q is not RFC3339: %v", got[0].CreatedAt, err)
	}
	if got[0].ID == "" {
		t.Fatal("message ID must not be empty")
	}
}

func TestDemoMemoryMailerConcurrentSendAndRead(t *testing.T) {
	m := newTestMailer()
	const workers, sends = 8, 25
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		to := "even@example.com"
		if w%2 == 1 {
			to = "odd@example.com"
		}
		wg.Add(2)
		go func(to string) {
			defer wg.Done()
			for i := 0; i < sends; i++ {
				_ = m.Send(context.Background(), signet.Message{
					To: to, Subject: "concurrent test", TextBody: fmt.Sprintf("%s %d", to, i),
				})
			}
		}(to)
		go func() {
			defer wg.Done()
			for i := 0; i < sends; i++ {
				_ = m.Messages("even@example.com")
				_ = m.Messages("ODD@example.com")
			}
		}()
	}
	wg.Wait()

	// The ring is global: the two addresses together must exactly fill the
	// last demoInboxCapacity sends, with no message leaking into the other
	// address's query. The ODD@example.com spelling exercises the
	// case-insensitive match.
	even := m.Messages("even@example.com")
	odd := m.Messages("ODD@example.com")
	if len(even)+len(odd) != demoInboxCapacity {
		t.Fatalf("ring holds %d+%d messages, want the two addresses to fill the cap of %d",
			len(even), len(odd), demoInboxCapacity)
	}
	for _, msg := range even {
		if msg.To != "even@example.com" {
			t.Fatalf("even inbox leaked a message for %q", msg.To)
		}
	}
	for _, msg := range odd {
		if msg.To != "odd@example.com" {
			t.Fatalf("odd inbox leaked a message for %q", msg.To)
		}
	}
}

func TestDemoInboxExtraction(t *testing.T) {
	link := "http://app.test/auth/verify?token=abc123"
	cases := []struct {
		name      string
		body      string
		wantURL   string
		wantToken string
		wantCode  string
	}{
		{
			name:      "verification link carries url and token",
			body:      "Hello Ada,\n\nVerify your email address:\n" + link + "\n\nThis link expires soon.\n",
			wantURL:   link,
			wantToken: "abc123",
		},
		{
			name:     "otp body carries the six-digit code",
			body:     "Hello Ada,\n\nYour sign-in code is 654321.\n\nThis code expires soon.\n",
			wantCode: "654321",
		},
		{
			name: "password-changed notice has neither",
			body: "Hello Ada,\n\nYour password was changed. If you did not do this, contact support.\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestMailer()
			if err := m.Send(context.Background(), signet.Message{
				To: "ada@example.com", Subject: "extraction test", TextBody: tc.body,
			}); err != nil {
				t.Fatalf("send: %v", err)
			}
			got := m.Messages("ada@example.com")
			if len(got) != 1 {
				t.Fatalf("got %d messages, want 1", len(got))
			}
			msg := got[0]
			if msg.URL != tc.wantURL {
				t.Errorf("url = %q, want %q", msg.URL, tc.wantURL)
			}
			if msg.Token != tc.wantToken {
				t.Errorf("token = %q, want %q", msg.Token, tc.wantToken)
			}
			if msg.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", msg.Code, tc.wantCode)
			}
			if msg.Body != tc.body {
				t.Errorf("body not stored verbatim")
			}
		})
	}
}

func TestDemoInboxEndpoint(t *testing.T) {
	m := newTestMailer()
	send := func(to, body string) {
		t.Helper()
		if err := m.Send(context.Background(), signet.Message{
			To: to, Subject: "endpoint test", TextBody: body,
		}); err != nil {
			t.Fatalf("send to %s: %v", to, err)
		}
	}
	send("user@example.com", "first\nhttp://app.test/auth/magic?token=tok-first")
	send("other@example.com", "someone else entirely")
	send("user@example.com", "second\nhttp://app.test/auth/magic?token=tok-second")
	send("user@example.com", "Your sign-in code is 123456.")

	handler := m.Handler()

	t.Run("requires email parameter", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/demo/inbox", nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("missing email: status = %d, want 400", rec.Code)
		}
	})

	t.Run("matches case-insensitively, newest first", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/demo/inbox?email=User%40Example.com", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("content-type = %q, want application/json", ct)
		}
		var res struct {
			Messages []DemoMessage `json:"messages"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if len(res.Messages) != 3 {
			t.Fatalf("got %d messages, want 3", len(res.Messages))
		}
		want := []struct{ body, url, token, code string }{
			{"Your sign-in code is 123456.", "", "", "123456"},
			{"second\nhttp://app.test/auth/magic?token=tok-second", "http://app.test/auth/magic?token=tok-second", "tok-second", ""},
			{"first\nhttp://app.test/auth/magic?token=tok-first", "http://app.test/auth/magic?token=tok-first", "tok-first", ""},
		}
		for i, w := range want {
			got := res.Messages[i]
			if got.Body != w.body || got.URL != w.url || got.Token != w.token || got.Code != w.code {
				t.Errorf("message %d = %+v, want body/url/token/code %q/%q/%q/%q", i, got, w.body, w.url, w.token, w.code)
			}
			if got.To != "user@example.com" {
				t.Errorf("message %d to = %q, want user@example.com", i, got.To)
			}
		}
	})

	t.Run("never leaks other recipients", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/demo/inbox?email=other@example.com", nil))
		var res struct {
			Messages []DemoMessage `json:"messages"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if len(res.Messages) != 1 {
			t.Fatalf("got %d messages, want 1", len(res.Messages))
		}
		if res.Messages[0].To != "other@example.com" {
			t.Fatalf("to = %q, want other@example.com", res.Messages[0].To)
		}
	})

	t.Run("unknown email returns empty array", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/demo/inbox?email=nobody@example.com", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if body := rec.Body.String(); body != "{\"messages\":[]}\n" {
			t.Fatalf("body = %q, want an empty messages array", body)
		}
	})
}
