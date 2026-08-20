package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// tokenBytes is the entropy in a session or CSRF token. 256 bits is far beyond
// guessable and costs nothing.
const tokenBytes = 32

// NewToken returns a random token and its storage hash.
//
// Only the hash is ever persisted. A stolen database therefore yields no usable
// session cookies, which is the difference between a data breach and an
// immediate account takeover.
func NewToken() (raw string, hash []byte, err error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("auth: generate token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, HashToken(raw), nil
}

// HashToken returns the storage hash for a token.
//
// SHA-256 without a salt or stretching is correct here, unlike for passwords: the
// input is 256 bits of uniform randomness, so there is no dictionary to attack
// and no benefit to slowing verification down. Session lookup happens on every
// request and must stay cheap.
func HashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
