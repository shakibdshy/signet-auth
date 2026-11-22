package auth

import (
	"context"

	"github.com/shakibdshy/signet/internal/core"
)

// checkBreach rejects a password that the configured BreachChecker reports as
// compromised. Without a checker it is a no-op.
func checkBreach(ctx context.Context, checker core.BreachChecker, password string) error {
	if checker == nil {
		return nil
	}
	compromised, err := checker.Check(ctx, password)
	if err != nil {
		return err
	}
	if compromised {
		return core.ErrPasswordCompromised
	}
	return nil
}
