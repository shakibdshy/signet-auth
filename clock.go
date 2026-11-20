package signet

import (
	"time"

	"github.com/shakibdshy/signet/internal/core"
)

// Clock supplies the current time so time-dependent behaviour can be tested
// without waiting.
type Clock = core.Clock

// SystemClock is the production Clock, backed by time.Now.
type SystemClock struct{}

// Now returns the current local time.
func (SystemClock) Now() time.Time { return time.Now() }
