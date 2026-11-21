package auth

import (
	"errors"
	"testing"

	"github.com/shakibdshy/signet/internal/core"
)

func TestValidateChangePassword(t *testing.T) {
	valid := core.ChangePasswordInput{
		UserID: "user-1", CurrentPassword: "old", NewPassword: "new-password",
	}
	tests := []struct {
		name string
		in   core.ChangePasswordInput
		want error
	}{
		{"empty user id", core.ChangePasswordInput{CurrentPassword: "old", NewPassword: "new-password"}, core.ErrInvalidCredentials},
		{"empty current", core.ChangePasswordInput{UserID: "user-1", NewPassword: "new-password"}, core.ErrInvalidCredentials},
		{"empty new", core.ChangePasswordInput{UserID: "user-1", CurrentPassword: "old"}, core.ErrInvalidCredentials},
		{"below minimum", core.ChangePasswordInput{UserID: "user-1", CurrentPassword: "old", NewPassword: "x"}, core.ErrPasswordTooShort},
		{"above maximum", core.ChangePasswordInput{UserID: "user-1", CurrentPassword: "old", NewPassword: string(make([]byte, 129))}, core.ErrPasswordTooLong},
		{"valid", valid, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validateChangePassword(tc.in, 8, 128)
			if !errors.Is(got, tc.want) {
				t.Errorf("error = %v, want %v", got, tc.want)
			}
		})
	}
}
