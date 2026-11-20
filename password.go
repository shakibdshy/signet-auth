package signet

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/shakibdshy/signet/internal/core"
	"golang.org/x/crypto/argon2"
)

// PasswordHasher stores and verifies password verifiers. The encoded value
// returned by Hash carries its algorithm and parameters so it can be upgraded.
type PasswordHasher = core.PasswordHasher

// Default Argon2id parameters follow the OWASP Password Storage Cheat Sheet:
// 19 MiB of memory, two iterations and parallelism one.
const (
	defaultArgonTime    uint32 = 2
	defaultArgonMemory  uint32 = 19456
	defaultArgonThreads uint8  = 1
	defaultArgonKeyLen  uint32 = 32
	defaultArgonSaltLen uint32 = 16
)

// Bounds on parameters read from a stored verifier. Without them a tampered
// verifier could make Verify allocate unbounded memory or spin for a long time.
const (
	maxArgonMemory  uint32 = 256 * 1024
	maxArgonTime    uint32 = 10
	maxArgonThreads uint8  = 16
	maxArgonKeyLen  uint32 = 128
	maxArgonSaltLen uint32 = 64
)

// Argon2idHasher stores password verifiers as Argon2id PHC strings. Its zero
// value uses the OWASP-recommended parameters.
type Argon2idHasher struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

type argonParams struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func (h Argon2idHasher) params() (time, memory uint32, threads uint8, keyLen, saltLen uint32) {
	time, memory, threads, keyLen, saltLen = h.Time, h.Memory, h.Threads, h.KeyLen, h.SaltLen
	if time == 0 {
		time = defaultArgonTime
	}
	if memory == 0 {
		memory = defaultArgonMemory
	}
	if threads == 0 {
		threads = defaultArgonThreads
	}
	if keyLen == 0 {
		keyLen = defaultArgonKeyLen
	}
	if saltLen == 0 {
		saltLen = defaultArgonSaltLen
	}
	return time, memory, threads, keyLen, saltLen
}

// Hash returns a PHC-format Argon2id verifier with a fresh random salt.
func (h Argon2idHasher) Hash(ctx context.Context, password string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	time, memory, threads, keyLen, saltLen := h.params()
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("signet: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether password matches an Argon2id PHC verifier.
func (h Argon2idHasher) Verify(ctx context.Context, encoded, password string) (bool, error) {
	params, salt, key, err := parseArgonVerifier(encoded)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, params.keyLen)
	return subtle.ConstantTimeCompare(got, key) == 1, nil
}

// NeedsRehash reports whether a verifier is missing, malformed, or was created
// with parameters different from this hasher's effective settings.
func (h Argon2idHasher) NeedsRehash(encoded string) bool {
	params, salt, _, err := parseArgonVerifier(encoded)
	if err != nil {
		return true
	}
	time, memory, threads, keyLen, saltLen := h.params()
	return params.time != time || params.memory != memory || params.threads != threads ||
		params.keyLen != keyLen || int64(len(salt)) != int64(saltLen)
}

func parseArgonVerifier(encoded string) (argonParams, []byte, []byte, error) {
	var zero argonParams
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return zero, nil, nil, errors.New("signet: malformed argon2id verifier")
	}
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return zero, nil, nil, errors.New("signet: malformed argon2id parameters")
	}
	memory, err := parseBoundedUint(strings.TrimPrefix(fields[0], "m="), maxArgonMemory)
	if err != nil {
		return zero, nil, nil, err
	}
	time, err := parseBoundedUint(strings.TrimPrefix(fields[1], "t="), maxArgonTime)
	if err != nil {
		return zero, nil, nil, err
	}
	threads64, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "p="), 10, 8)
	if err != nil || threads64 == 0 || threads64 > uint64(maxArgonThreads) {
		return zero, nil, nil, errors.New("signet: invalid argon2id parameter")
	}
	threads := uint8(threads64)
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 || int64(len(salt)) > int64(maxArgonSaltLen) {
		return zero, nil, nil, errors.New("signet: malformed argon2id salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 || int64(len(key)) > int64(maxArgonKeyLen) {
		return zero, nil, nil, errors.New("signet: malformed argon2id key")
	}
	//nolint:gosec // G115: the key length is bounded to 128 bytes by the check above.
	return argonParams{time: time, memory: memory, threads: threads, keyLen: uint32(len(key))}, salt, key, nil
}

func parseBoundedUint(raw string, limit uint32) (uint32, error) {
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || value == 0 || value > uint64(limit) {
		return 0, errors.New("signet: invalid argon2id parameter")
	}
	return uint32(value), nil
}
