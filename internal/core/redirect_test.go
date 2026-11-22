package core

import "testing"

func TestRedirectPermittedPatterns(t *testing.T) {
	patterns := []string{"https://*.example.com"}
	allowed := []string{"https://exact.example.org/callback"}
	for _, redirect := range []string{
		"https://exact.example.org/callback",
		"https://app.example.com/welcome",
		"https://a.b.example.com/deep/path",
	} {
		if !RedirectPermitted(redirect, allowed, patterns) {
			t.Errorf("redirect %q should be permitted", redirect)
		}
	}
	for _, redirect := range []string{
		"https://example.com/welcome",
		"https://example.com.evil.test/welcome",
		"http://app.example.com/welcome",
		"https://*.example.com/welcome",
	} {
		if RedirectPermitted(redirect, allowed, patterns) {
			t.Errorf("redirect %q should be rejected", redirect)
		}
	}
}

func TestValidateRedirectPatterns(t *testing.T) {
	for _, pattern := range []string{
		"https://*.example.com",
		"https://*.a.b.example.com",
	} {
		if err := ValidateRedirectPatterns([]string{pattern}); err != nil {
			t.Errorf("pattern %q should be valid: %v", pattern, err)
		}
	}
	for _, pattern := range []string{
		"http://*.example.com",
		"https://*.example.com/welcome",
		"https://app.example.com:8443",
		"https://example.com",
		"https://app.*.com",
		"*://example.com",
		"https://*.com",
	} {
		if err := ValidateRedirectPatterns([]string{pattern}); err == nil {
			t.Errorf("pattern %q should be rejected", pattern)
		}
	}
}
