package signet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"
)

const oauthStateTTL = 10 * time.Minute
const oauthLinkTTL = 10 * time.Minute

type oauthState struct {
	Provider  string    `json:"provider"`
	Redirect  string    `json:"redirect"`
	Verifier  string    `json:"verifier"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

type oauthLinkPayload struct {
	Identity  OAuthIdentity `json:"identity"`
	ExpiresAt time.Time     `json:"expires_at"`
}

func (c *Client) sealValue(value any) (string, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(c.cfg.OAuth.StateKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (c *Client) openValue(raw string, out any) error {
	sealed, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return ErrOAuthInvalidState
	}
	block, err := aes.NewCipher(c.cfg.OAuth.StateKey)
	if err != nil {
		return ErrOAuthInvalidState
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ErrOAuthInvalidState
	}
	if len(sealed) < gcm.NonceSize() {
		return ErrOAuthInvalidState
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ErrOAuthInvalidState
	}
	if err := json.Unmarshal(plaintext, out); err != nil {
		return ErrOAuthInvalidState
	}
	return nil
}

func (c *Client) sealState(state oauthState) (string, error) {
	return c.sealValue(state)
}

func (c *Client) openState(raw string) (*oauthState, error) {
	var state oauthState
	if err := c.openValue(raw, &state); err != nil {
		return nil, ErrOAuthInvalidState
	}
	if !c.cfg.Clock.Now().Before(state.ExpiresAt) {
		return nil, ErrOAuthInvalidState
	}
	return &state, nil
}

func (c *Client) sealLink(identity OAuthIdentity) (string, error) {
	return c.sealValue(oauthLinkPayload{Identity: identity, ExpiresAt: c.cfg.Clock.Now().Add(oauthLinkTTL)})
}

func (c *Client) openLink(raw string) (*oauthLinkPayload, error) {
	var payload oauthLinkPayload
	if err := c.openValue(raw, &payload); err != nil {
		return nil, ErrTokenInvalid
	}
	if !c.cfg.Clock.Now().Before(payload.ExpiresAt) {
		return nil, ErrTokenInvalid
	}
	return &payload, nil
}

func (c *Client) redirectAllowed(redirect string) bool {
	for _, allowed := range c.cfg.OAuth.AllowedRedirects {
		if redirect == allowed {
			return true
		}
	}
	return false
}

func (c *Client) oauthProvider(name string) OAuthProvider {
	for _, provider := range c.cfg.OAuth.Providers {
		if provider.Name() == name {
			return provider
		}
	}
	return nil
}
