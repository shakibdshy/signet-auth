package auth

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/shakibdshy/signet/internal/core"
)

const usernameProvider = "username"

var usernamePattern = regexp.MustCompile(`^[a-z0-9_.]+$`)

func (s *Service) normalizeUsername(raw string) string {
	value := strings.TrimSpace(raw)
	if s.deps.Username != nil && s.deps.Username.Normalize != nil {
		return s.deps.Username.Normalize(value)
	}
	return strings.ToLower(value)
}

func (s *Service) validateUsername(raw string) string {
	username := s.normalizeUsername(raw)
	minLength, maxLength := 3, 30
	if s.deps.Username != nil {
		if s.deps.Username.MinLength > 0 {
			minLength = s.deps.Username.MinLength
		}
		if s.deps.Username.MaxLength > 0 {
			maxLength = s.deps.Username.MaxLength
		}
	}
	if len(username) < minLength || len(username) > maxLength || !usernamePattern.MatchString(username) {
		return ""
	}
	if s.deps.Username != nil {
		for _, reserved := range s.deps.Username.Reserved {
			if username == strings.ToLower(reserved) {
				return ""
			}
		}
	}
	return username
}

func (s *Service) findUserByUsername(ctx context.Context, raw string) (*core.User, error) {
	username := s.normalizeUsername(raw)
	if username == "" {
		return nil, core.ErrNotFound
	}
	account, err := s.deps.Store.AccountByProvider(ctx, usernameProvider, username)
	if err != nil {
		return nil, err
	}
	return s.deps.Store.UserByID(ctx, account.UserID)
}

// claimUsername ensures a Username is free before a User is created.
func (s *Service) claimUsername(ctx context.Context, raw string) (string, error) {
	username := s.validateUsername(raw)
	if username == "" {
		return "", core.ErrInvalidUsername
	}
	_, err := s.deps.Store.AccountByProvider(ctx, usernameProvider, username)
	if err == nil {
		return "", core.ErrUsernameTaken
	}
	if !errors.Is(err, core.ErrNotFound) {
		return "", err
	}
	return username, nil
}
