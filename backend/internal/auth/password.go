// Package auth handles password verification, browser sessions, CSRF tokens, and
// the single-use tickets that authenticate WebSocket upgrades.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Password length bounds.
//
// The minimum is 12 rather than 8: this is the credential guarding an entire
// estate's SSH keys, and an eight-character password is within reach of offline
// cracking if the database is ever exposed. The maximum exists because Argon2
// cost scales with input, so an unbounded password field is a denial-of-service
// vector on the login endpoint.
const (
	MinPasswordLength = 12
	MaxPasswordLength = 1024
)

// ErrPasswordTooShort and friends are returned by ValidatePassword.
var (
	ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	ErrPasswordTooLong  = fmt.Errorf("password must be at most %d characters", MaxPasswordLength)
	ErrInvalidHash      = errors.New("auth: password hash is not a recognised argon2id encoding")
	ErrUnsupportedAlgo  = errors.New("auth: unsupported password hash algorithm")
)

// Argon2Params configures password hashing.
type Argon2Params struct {
	// MemoryKiB is the memory cost.
	MemoryKiB uint32
	// Iterations is the time cost.
	Iterations uint32
	// Parallelism is the number of lanes.
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultArgon2 follows the RFC 9106 second recommended configuration: 64 MiB,
// three passes, four lanes. On commodity hardware this takes tens of
// milliseconds, which is imperceptible at login and expensive in bulk.
var DefaultArgon2 = Argon2Params{
	MemoryKiB:   64 * 1024,
	Iterations:  3,
	Parallelism: 4,
	SaltLen:     16,
	KeyLen:      32,
}

// testArgon2 is the reduced cost used by tests, exported so other packages'
// tests can hash quickly without hard-coding parameters.
var TestArgon2 = Argon2Params{
	MemoryKiB:   8 * 1024,
	Iterations:  1,
	Parallelism: 1,
	SaltLen:     16,
	KeyLen:      32,
}

// ValidatePassword checks a candidate against the length policy.
//
// Deliberately no character-class rules. They push users towards predictable
// substitutions and add little entropy compared with length, and NIST dropped
// the recommendation years ago.
func ValidatePassword(password string) error {
	switch {
	case len(password) < MinPasswordLength:
		return ErrPasswordTooShort
	case len(password) > MaxPasswordLength:
		return ErrPasswordTooLong
	}
	return nil
}

// HashPassword produces an encoded argon2id hash.
func HashPassword(password string, p Argon2Params) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLen)
	return encodeHash(p, salt, key), nil
}

// VerifyPassword checks a password against an encoded hash.
//
// needsRehash reports that the stored hash used weaker parameters than the
// current policy, so the caller can transparently upgrade it on a successful
// login. That is how parameters get stronger over time without forcing resets.
func VerifyPassword(encoded, password string, current Argon2Params) (ok bool, needsRehash bool, err error) {
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.MemoryKiB, p.Parallelism, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	return true, weakerThan(p, current), nil
}

func weakerThan(have, want Argon2Params) bool {
	return have.MemoryKiB < want.MemoryKiB ||
		have.Iterations < want.Iterations ||
		have.Parallelism < want.Parallelism ||
		have.KeyLen < want.KeyLen
}

var (
	dummyOnce sync.Once
	dummyHash string
)

// DummyVerify performs a password verification against a throwaway hash.
//
// Called when the username does not exist, so a failed login costs the same time
// whether or not the account is real. Without this, response timing enumerates
// valid usernames, which is the first step of a targeted attack.
func DummyVerify(password string, p Argon2Params) {
	dummyOnce.Do(func() {
		// Any value works; it is never compared successfully.
		h, err := HashPassword("axt-term-timing-equalisation-placeholder", p)
		if err == nil {
			dummyHash = h
		}
	})
	if dummyHash == "" {
		return
	}
	_, _, _ = VerifyPassword(dummyHash, password, p)
}

// passwordAlphabet excludes characters that are easily confused when a generated
// password is read off a terminal and typed elsewhere: 0/O, 1/l/I.
const passwordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_"

// GeneratePassword returns a random password of the given length.
//
// Used for the bootstrap administrator, where the account must exist before a
// human can choose a password. The result is printed once and the account is
// flagged must-change.
func GeneratePassword(length int) (string, error) {
	if length < MinPasswordLength {
		length = MinPasswordLength
	}
	out := make([]byte, length)
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generate password: %w", err)
	}
	// Modulo bias is negligible here: the alphabet is 59 characters against a
	// 256-value byte, and the entropy at 24 characters is far beyond what the
	// bias removes.
	for i, b := range buf {
		out[i] = passwordAlphabet[int(b)%len(passwordAlphabet)]
	}
	return string(out), nil
}

func encodeHash(p Argon2Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

func decodeHash(encoded string) (p Argon2Params, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, key]
	if len(parts) != 6 || parts[0] != "" {
		return p, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return p, nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgo, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("%w: argon2 version %d", ErrUnsupportedAlgo, version)
	}

	for _, field := range strings.Split(parts[3], ",") {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			return p, nil, nil, ErrInvalidHash
		}
		n, convErr := strconv.ParseUint(kv[1], 10, 32)
		if convErr != nil {
			return p, nil, nil, ErrInvalidHash
		}
		switch kv[0] {
		case "m":
			p.MemoryKiB = uint32(n)
		case "t":
			p.Iterations = uint32(n)
		case "p":
			if n > 255 {
				return p, nil, nil, ErrInvalidHash
			}
			p.Parallelism = uint8(n)
		default:
			return p, nil, nil, ErrInvalidHash
		}
	}
	if p.MemoryKiB == 0 || p.Iterations == 0 || p.Parallelism == 0 {
		return p, nil, nil, ErrInvalidHash
	}

	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if len(salt) == 0 || len(key) == 0 {
		return p, nil, nil, ErrInvalidHash
	}
	p.SaltLen = uint32(len(salt))
	p.KeyLen = uint32(len(key))
	return p, salt, key, nil
}
