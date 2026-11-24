// Package passkey wraps WebAuthn ceremony verification behind Signet's protocol seam.
package passkey

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/shakibdshy/signet-auth/internal/core"
)

// Protocol implements core.PasskeyProtocol with go-webauthn.
type Protocol struct {
	wa     *wa.WebAuthn
	Lookup func(context.Context, string) (*core.WebAuthnCredential, error)
}

// NewProtocol returns a verifier for the given Relying party configuration.
func NewProtocol(cfg *core.PasskeysConfig) (*Protocol, error) {
	uv := protocol.VerificationRequired
	attestation := protocol.ConveyancePreference("none")
	name := "Signet"
	origins := []string{}
	if cfg != nil {
		if cfg.RPDisplayName != "" {
			name = cfg.RPDisplayName
		}
		origins = append(origins, cfg.RPOrigins...)
	}
	w, err := wa.New(&wa.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         name,
		RPOrigins:             origins,
		AttestationPreference: attestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: boolPtr(true),
			UserVerification:   uv,
		},
	})
	if err != nil {
		return nil, err
	}
	return &Protocol{wa: w}, nil
}

func boolPtr(v bool) *bool { return &v }

// webUser adapts a Signet User and its credentials to go-webauthn.
type webUser struct {
	id          string
	name        string
	displayName string
	credentials []wa.Credential
}

func (u *webUser) WebAuthnID() []byte                   { return []byte(u.id) }
func (u *webUser) WebAuthnName() string                 { return u.name }
func (u *webUser) WebAuthnDisplayName() string          { return u.displayName }
func (u *webUser) WebAuthnCredentials() []wa.Credential { return u.credentials }

func toCredential(c *core.WebAuthnCredential) wa.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return wa.Credential{
		ID: decodedID(c.ID), PublicKey: c.PublicKey, Transport: transports,
		Flags: wa.CredentialFlags{
			BackupEligible: c.BackupEligible, BackupState: c.BackupState,
		},
		Authenticator: wa.Authenticator{
			AAGUID: decodedID(c.AAGUID), SignCount: c.SignCount,
		},
	}
}

func fromCredential(c *wa.Credential, userID string) *core.WebAuthnCredential {
	id := hex.EncodeToString(c.ID)
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return &core.WebAuthnCredential{
		ID: id, UserID: userID, PublicKey: c.PublicKey,
		AAGUID:    hex.EncodeToString(c.Authenticator.AAGUID),
		SignCount: c.Authenticator.SignCount, Transports: transports,
		BackupEligible: c.Flags.BackupEligible, BackupState: c.Flags.BackupState,
	}
}

// BeginRegistration starts a discoverable registration ceremony.
func (p *Protocol) BeginRegistration(_ context.Context, userID, name string, credentials []*core.WebAuthnCredential) ([]byte, string, error) {
	user := &webUser{id: userID, name: name, displayName: name}
	for _, c := range credentials {
		user.credentials = append(user.credentials, toCredential(c))
	}
	creation, session, err := p.wa.BeginRegistration(user)
	if err != nil {
		return nil, "", err
	}
	options, err := json.Marshal(creation)
	if err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return nil, "", err
	}
	return options, string(data), nil
}

// FinishRegistration verifies the authenticator response and builds a credential record.
func (p *Protocol) FinishRegistration(_ context.Context, data string, response []byte) (*core.WebAuthnCredential, error) {
	var session wa.SessionData
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, err
	}
	user := &webUser{id: string(session.UserID), name: string(session.UserID), displayName: string(session.UserID)}
	req, err := http.NewRequest(http.MethodPost, "/", bytes.NewReader(response))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	credential, err := p.wa.FinishRegistration(user, session, req)
	if err != nil {
		return nil, err
	}
	return fromCredential(credential, string(session.UserID)), nil
}

// BeginLogin starts a discoverable authentication ceremony.
func (p *Protocol) BeginLogin(_ context.Context) ([]byte, string, error) {
	assertion, session, err := p.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", err
	}
	options, err := json.Marshal(assertion)
	if err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return nil, "", err
	}
	return options, string(data), nil
}

// FinishLogin verifies a discoverable assertion and returns the User and credential.
func (p *Protocol) FinishLogin(_ context.Context, data string, response []byte) (string, *core.WebAuthnCredential, error) {
	var session wa.SessionData
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return "", nil, err
	}
	handler := func(rawID, userHandle []byte) (wa.User, error) {
		userID := string(userHandle)
		credentials := []*core.WebAuthnCredential{}
		if p.Lookup != nil {
			if credential, err := p.Lookup(context.Background(), hex.EncodeToString(rawID)); err == nil && credential != nil {
				userID = credential.UserID
				credentials = append(credentials, credential)
			}
		}
		if userID == "" {
			userID = "unknown"
		}
		user := &webUser{id: userID, name: userID, displayName: userID}
		for _, c := range credentials {
			user.credentials = append(user.credentials, toCredential(c))
		}
		return user, nil
	}
	req, err := http.NewRequest(http.MethodPost, "/", bytes.NewReader(response))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	user, credential, err := p.wa.FinishPasskeyLogin(handler, session, req)
	if err != nil {
		return "", nil, err
	}
	return user.WebAuthnName(), fromCredential(credential, user.WebAuthnName()), nil
}

// Ensure the seam is satisfied at compile time.
var _ core.PasskeyProtocol = (*Protocol)(nil)

func decodedID(value string) []byte {
	b, _ := hex.DecodeString(value)
	return b
}

// Validate checks a Relying party configuration without retaining the verifier.
func Validate(cfg *core.PasskeysConfig) error {
	if cfg == nil {
		return nil
	}
	for _, raw := range cfg.RPOrigins {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("invalid relying party origin %q", raw)
		}
	}
	_, err := NewProtocol(cfg)
	return err
}
