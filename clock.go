package signet

import "time"

// Clock supplies the current time so time-dependent behaviour can be tested
// without waiting.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
}

// SystemClock is the production Clock, backed by time.Now.
type SystemClock struct{}

// Now returns the current local time.
func (SystemClock) Now() time.Time { return time.Now() }
