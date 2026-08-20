// Package sshx is AXT-Term's SSH engine: dialing (including jump-host chains),
// host-key verification, connection pooling, interactive PTY sessions,
// non-interactive execution, and port forwarding.
//
// Nothing here shells out to an ssh binary. Everything runs in-process through
// golang.org/x/crypto/ssh, which means there is no command line to quote and
// therefore no argument-injection surface at all.
package sshx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/axt-term/axt-term/backend/internal/store"
	"golang.org/x/crypto/ssh"
)

// Host-key policies.
const (
	PolicyTOFU   = "tofu"
	PolicyStrict = "strict"
)

// HostKeyStore is the part of the store host-key verification needs.
type HostKeyStore interface {
	TrustedHostKey(ctx context.Context, hostname string, port int, keyType string) (*store.HostKey, error)
	HostKeysFor(ctx context.Context, hostname string, port int) ([]*store.HostKey, error)
	TouchHostKey(ctx context.Context, id string) error
}

// UnknownHostKeyError reports a host presenting a key we have never seen.
//
// The verification callback returns this rather than blocking to ask the user.
// Prompting from inside the callback would hold an SSH handshake open for as long
// as the person takes to read a fingerprint; returning an error lets the API
// respond with state "pending_hostkey", collect the decision, and dial again.
type UnknownHostKeyError struct {
	Hostname    string
	Port        int
	KeyType     string
	Fingerprint string
	PublicKey   []byte
}

func (e *UnknownHostKeyError) Error() string {
	return fmt.Sprintf("host key for %s is not trusted (%s %s)",
		net.JoinHostPort(e.Hostname, strconv.Itoa(e.Port)), e.KeyType, e.Fingerprint)
}

// MismatchedHostKeyError reports a host presenting a different key than the one
// previously trusted.
//
// This is always fatal and has no override in the connect path. A changed host key
// means either a legitimate rebuild or an active interception, and the two are
// indistinguishable from here -- so clearing it is a deliberate administrative
// action on the host-keys screen, not a checkbox on a connection dialog.
type MismatchedHostKeyError struct {
	Hostname    string
	Port        int
	KeyType     string
	Expected    string
	Actual      string
	FirstSeenAt string
}

func (e *MismatchedHostKeyError) Error() string {
	return fmt.Sprintf(
		"HOST KEY MISMATCH for %s: expected %s %s (first trusted %s) but the server offered %s. "+
			"This is either a rebuilt host or an interception attempt. "+
			"Verify out of band, then revoke the stored key to continue",
		net.JoinHostPort(e.Hostname, strconv.Itoa(e.Port)),
		e.KeyType, e.Expected, e.FirstSeenAt, e.Actual)
}

// RevokedHostKeyError reports a key that an administrator explicitly revoked.
type RevokedHostKeyError struct {
	Hostname string
	Port     int
	KeyType  string
}

func (e *RevokedHostKeyError) Error() string {
	return fmt.Sprintf("host key for %s (%s) has been revoked",
		net.JoinHostPort(e.Hostname, strconv.Itoa(e.Port)), e.KeyType)
}

// Verifier checks presented host keys against the trust store.
type Verifier struct {
	store  HostKeyStore
	policy string
}

// NewVerifier creates a verifier. An unrecognised policy falls back to strict,
// because the safe default when configuration is unclear is to refuse.
func NewVerifier(st HostKeyStore, policy string) *Verifier {
	if policy != PolicyTOFU {
		policy = PolicyStrict
	}
	return &Verifier{store: st, policy: policy}
}

// Callback returns an ssh.HostKeyCallback bound to a specific endpoint.
//
// The endpoint comes from the inventory rather than from the address string the
// SSH library passes in, because through a jump host that string is whatever the
// bastion resolved -- and trust must be keyed on what the operator configured.
func (v *Verifier) Callback(ctx context.Context, hostname string, port int) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		keyType := key.Type()
		fingerprint := ssh.FingerprintSHA256(key)

		trusted, err := v.store.TrustedHostKey(ctx, hostname, port, keyType)
		switch {
		case err == nil:
			if trusted.FingerprintSHA256 == fingerprint {
				// Best-effort: failing to update a timestamp must not fail a
				// connection.
				_ = v.store.TouchHostKey(ctx, trusted.ID)
				return nil
			}
			return &MismatchedHostKeyError{
				Hostname:    hostname,
				Port:        port,
				KeyType:     keyType,
				Expected:    trusted.FingerprintSHA256,
				Actual:      fingerprint,
				FirstSeenAt: trusted.FirstSeenAt.Format("2006-01-02"),
			}

		case errors.Is(err, store.ErrNotFound):
			// Distinguish "never seen" from "seen and revoked": the second must
			// not be silently re-trusted by the first-contact flow.
			existing, listErr := v.store.HostKeysFor(ctx, hostname, port)
			if listErr == nil {
				for _, k := range existing {
					if k.KeyType == keyType && k.RevokedAt != nil {
						return &RevokedHostKeyError{Hostname: hostname, Port: port, KeyType: keyType}
					}
				}
			}
			if v.policy == PolicyStrict {
				return fmt.Errorf("strict host key policy: %w", &UnknownHostKeyError{
					Hostname: hostname, Port: port, KeyType: keyType,
					Fingerprint: fingerprint, PublicKey: key.Marshal(),
				})
			}
			return &UnknownHostKeyError{
				Hostname: hostname, Port: port, KeyType: keyType,
				Fingerprint: fingerprint, PublicKey: key.Marshal(),
			}

		default:
			return fmt.Errorf("host key lookup failed: %w", err)
		}
	}
}

// AsUnknownHostKey extracts an UnknownHostKeyError from a wrapped dial error.
func AsUnknownHostKey(err error) (*UnknownHostKeyError, bool) {
	var target *UnknownHostKeyError
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}

// AsMismatchedHostKey extracts a MismatchedHostKeyError from a wrapped dial error.
func AsMismatchedHostKey(err error) (*MismatchedHostKeyError, bool) {
	var target *MismatchedHostKeyError
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}
