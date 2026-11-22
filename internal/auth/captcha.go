package auth

import (
	"context"
	"errors"

	"github.com/shakibdshy/signet/internal/core"
)

var defaultCaptchaEndpoints = []string{"signup", "signin", "send-password-reset"}

// checkCaptcha enforces a Captcha check for configured endpoints. It runs
// after rate limiting so unauthenticated traffic cannot hammer the provider.
func checkCaptcha(ctx context.Context, verifier core.CaptchaVerifier, endpoints []string, endpoint, token, remoteIP string) error {
	if verifier == nil {
		return nil
	}
	if len(endpoints) == 0 {
		endpoints = defaultCaptchaEndpoints
	}
	configured := false
	for _, name := range endpoints {
		if name == endpoint {
			configured = true
			break
		}
	}
	if !configured {
		return nil
	}
	if token == "" {
		return core.ErrCaptchaRequired
	}
	if err := verifier.Verify(ctx, token, remoteIP); err != nil {
		if errors.Is(err, core.ErrCaptchaInvalid) {
			return err
		}
		if err == nil {
			return nil
		}
		return core.ErrCaptchaUnavailable
	}
	return nil
}
