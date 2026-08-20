// Package crypto implements AXT-Term's credential encryption.
//
// # Design
//
// Envelope encryption with two levels:
//
//	master key (KEK)  -- from the environment, a file, or an Argon2id-derived
//	                     passphrase. Never stored in the database.
//	   wraps
//	data key (DEK)    -- one per credential, stored wrapped in the credentials
//	                     row.
//	   encrypts
//	secret ciphertext -- one row per field (password, private_key, passphrase).
//
// Two levels rather than one buys two things. Rotating the master key rewraps a
// few hundred small DEKs instead of re-encrypting every secret, so rotation is
// fast and its failure window is tiny. And each credential has an independent
// key, so a single-key compromise is not a whole-store compromise.
//
// # Associated data
//
// Every ciphertext is bound to its location with AES-GCM associated data:
//
//	DEK    AAD = "axt:dek:v1|"    + credentialID + "|" + keyVersion
//	secret AAD = "axt:secret:v1|" + credentialID + "|" + field
//
// This defeats an attacker with write access to the database who moves rows
// around: copying prod-db's wrapped DEK onto a credential they can read, or
// swapping a passphrase blob into the password field, both fail authentication
// rather than decrypting. Without AAD binding, both would work.
//
// # What this does not protect against
//
// An attacker who can read both the database and the master key -- root on the
// host, or a backup containing both -- recovers everything. Stated plainly
// because pretending otherwise would be worse than the limitation. External
// providers (Vault, and similar) are the answer to that threat and are what the
// provider column in the credentials table exists for.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// KeyLen is the required master key and DEK length.
const KeyLen = 32

// Blob layout constants.
const (
	blobFormatV1 = 0x01
	nonceLen     = 12 // AES-GCM standard nonce size
	tagLen       = 16
)

// AAD prefixes. Changing one of these is a breaking format change and requires
// a new blob format version.
const (
	aadDEKPrefix    = "axt:dek:v1|"
	aadSecretPrefix = "axt:secret:v1|"
	aadCanary       = "axt:canary:v1"
)

// canaryPlaintext is encrypted once at initialisation and stored in settings.
// Startup decrypts it to prove the configured master key is the one the data
// was encrypted with.
const canaryPlaintext = "axt-term master key canary v1"

// Sentinel errors callers distinguish.
var (
	// ErrWrongKey means authentication failed: the master key does not match,
	// the data was tampered with, or the blob was moved between records.
	ErrWrongKey = errors.New("crypto: decryption failed (wrong key, corrupt data, or relocated ciphertext)")
	// ErrMalformedBlob means the ciphertext is not a recognised envelope.
	ErrMalformedBlob = errors.New("crypto: malformed ciphertext blob")
	// ErrUnknownKeyVersion means a blob references a key version this keyring
	// does not hold, which happens if an old key was discarded before rotation
	// finished.
	ErrUnknownKeyVersion = errors.New("crypto: blob references an unknown key version")
)

// Field names for secret storage. These appear in associated data, so they are
// part of the on-disk format.
const (
	FieldPassword   = "password"
	FieldPrivateKey = "private_key"
	FieldPassphrase = "passphrase"
)

// KeySource describes where the master key comes from. Exactly one field must
// be set.
type KeySource struct {
	// Base64 is a base64-encoded 32-byte key, from AXT_MASTER_KEY.
	Base64 string
	// File is a path to a file containing the base64-encoded key. Preferred:
	// file permissions are a real boundary, whereas environment variables are
	// inherited by child processes and visible in container inspection.
	File string
	// Passphrase is derived with Argon2id. Convenient, weaker than a random key.
	Passphrase string
}

// IsZero reports whether no source was configured.
func (s KeySource) IsZero() bool {
	return s.Base64 == "" && s.File == "" && s.Passphrase == ""
}

// KDFParams holds Argon2id parameters for passphrase-derived keys. Stored in
// crypto_keys so the same passphrase derives the same key after a restart.
type KDFParams struct {
	Salt        []byte `json:"-"`
	MemoryKiB   uint32 `json:"m"`
	Iterations  uint32 `json:"t"`
	Parallelism uint8  `json:"p"`
}

// DefaultKDFParams returns parameters with a fresh random salt.
//
// 64 MiB / t=3 / p=4 follows the RFC 9106 second recommended configuration. The
// cost is paid once at startup, so it can be generous.
func DefaultKDFParams() (KDFParams, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return KDFParams{}, fmt.Errorf("crypto: generate KDF salt: %w", err)
	}
	return KDFParams{Salt: salt, MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 4}, nil
}

// Validate checks the parameters are usable and not absurdly weak.
func (p KDFParams) Validate() error {
	switch {
	case len(p.Salt) < 8:
		return errors.New("crypto: KDF salt must be at least 8 bytes")
	case p.MemoryKiB < 8*1024:
		return errors.New("crypto: KDF memory must be at least 8192 KiB")
	case p.Iterations < 1:
		return errors.New("crypto: KDF iterations must be at least 1")
	case p.Parallelism < 1:
		return errors.New("crypto: KDF parallelism must be at least 1")
	}
	return nil
}

// Derive turns a passphrase into a key.
func (p KDFParams) Derive(passphrase string) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if passphrase == "" {
		return nil, errors.New("crypto: passphrase is empty")
	}
	return argon2.IDKey([]byte(passphrase), p.Salt, p.Iterations, p.MemoryKiB, p.Parallelism, KeyLen), nil
}

// LoadMasterKey resolves a master key from its source.
//
// kdf is required only when the source is a passphrase; it is the persisted salt
// and parameters, so the same passphrase yields the same key across restarts.
func LoadMasterKey(src KeySource, kdf *KDFParams) ([]byte, error) {
	set := 0
	for _, present := range []bool{src.Base64 != "", src.File != "", src.Passphrase != ""} {
		if present {
			set++
		}
	}
	switch set {
	case 0:
		return nil, errors.New("crypto: no master key configured; set exactly one of AXT_MASTER_KEY, AXT_MASTER_KEY_FILE, or AXT_MASTER_PASSPHRASE")
	case 1:
	default:
		return nil, errors.New("crypto: more than one master key source configured; set exactly one of AXT_MASTER_KEY, AXT_MASTER_KEY_FILE, or AXT_MASTER_PASSPHRASE")
	}

	switch {
	case src.File != "":
		raw, err := os.ReadFile(src.File)
		if err != nil {
			return nil, fmt.Errorf("crypto: read master key file: %w", err)
		}
		key, err := decodeKey(string(raw))
		if err != nil {
			return nil, fmt.Errorf("crypto: master key file %s: %w", src.File, err)
		}
		return key, nil

	case src.Base64 != "":
		key, err := decodeKey(src.Base64)
		if err != nil {
			return nil, fmt.Errorf("crypto: AXT_MASTER_KEY: %w", err)
		}
		return key, nil

	default:
		if kdf == nil {
			return nil, errors.New("crypto: a passphrase source requires persisted KDF parameters")
		}
		return kdf.Derive(src.Passphrase)
	}
}

// decodeKey accepts standard or URL-safe base64, with or without padding, and
// tolerates surrounding whitespace so a key file written by `openssl rand -base64
// 32 > key` works without post-processing.
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	if s == "" {
		return nil, errors.New("value is empty")
	}

	var (
		key []byte
		err error
	)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if key, err = enc.DecodeString(s); err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.New("value is not valid base64")
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("key must decode to exactly %d bytes, got %d (generate one with: openssl rand -base64 32)", KeyLen, len(key))
	}
	return key, nil
}

// GenerateMasterKey returns a new random master key, base64-encoded. Used by
// `axt-admin key generate`.
func GenerateMasterKey() (string, error) {
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("crypto: generate master key: %w", err)
	}
	defer Zero(key)
	return base64.StdEncoding.EncodeToString(key), nil
}

// Keyring holds the master keys and performs all wrapping and encryption.
//
// It holds more than one version so that rotation can proceed incrementally:
// blobs still wrapped with an older version remain readable until they are
// rewrapped.
type Keyring struct {
	aeads   map[uint16]cipher.AEAD
	current uint16
}

// NewKeyring builds a keyring with one master key at the given version.
func NewKeyring(version uint16, masterKey []byte) (*Keyring, error) {
	if version == 0 {
		return nil, errors.New("crypto: key version must be 1 or greater")
	}
	aead, err := newAEAD(masterKey)
	if err != nil {
		return nil, err
	}
	return &Keyring{aeads: map[uint16]cipher.AEAD{version: aead}, current: version}, nil
}

// AddVersion registers an additional master key version without changing which
// one is current. Rotation loads the retired key this way so old blobs stay
// readable while they are rewrapped.
func (k *Keyring) AddVersion(version uint16, masterKey []byte) error {
	if version == 0 {
		return errors.New("crypto: key version must be 1 or greater")
	}
	if _, exists := k.aeads[version]; exists {
		return fmt.Errorf("crypto: key version %d already registered", version)
	}
	aead, err := newAEAD(masterKey)
	if err != nil {
		return err
	}
	k.aeads[version] = aead
	return nil
}

// SetCurrent makes an already-registered version the one used for new blobs.
func (k *Keyring) SetCurrent(version uint16) error {
	if _, ok := k.aeads[version]; !ok {
		return fmt.Errorf("crypto: key version %d is not registered", version)
	}
	k.current = version
	return nil
}

// CurrentVersion returns the version new blobs are wrapped with.
func (k *Keyring) CurrentVersion() uint16 { return k.current }

// Versions returns every registered version.
func (k *Keyring) Versions() []uint16 {
	out := make([]uint16, 0, len(k.aeads))
	for v := range k.aeads {
		out = append(out, v)
	}
	return out
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new GCM: %w", err)
	}
	return aead, nil
}

// NewDEK generates a data key for a credential and returns it both in plaintext
// (for immediate use) and wrapped (for storage).
//
// The caller must Zero the plaintext when finished with it.
func (k *Keyring) NewDEK(credentialID string) (dek, wrapped []byte, err error) {
	if credentialID == "" {
		return nil, nil, errors.New("crypto: credential id is required")
	}
	dek = make([]byte, KeyLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("crypto: generate data key: %w", err)
	}
	wrapped, err = k.WrapDEK(dek, credentialID)
	if err != nil {
		Zero(dek)
		return nil, nil, err
	}
	return dek, wrapped, nil
}

// WrapDEK encrypts a data key with the current master key.
//
// Layout: format(1) ‖ keyVersion(2, big endian) ‖ nonce(12) ‖ ciphertext ‖ tag.
// The key version travels with the blob so a rotation in progress can tell
// which master key a given row still needs.
func (k *Keyring) WrapDEK(dek []byte, credentialID string) ([]byte, error) {
	if len(dek) != KeyLen {
		return nil, fmt.Errorf("crypto: data key must be %d bytes, got %d", KeyLen, len(dek))
	}
	if credentialID == "" {
		return nil, errors.New("crypto: credential id is required")
	}
	aead := k.aeads[k.current]
	if aead == nil {
		return nil, ErrUnknownKeyVersion
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}

	header := make([]byte, 3)
	header[0] = blobFormatV1
	binary.BigEndian.PutUint16(header[1:], k.current)

	out := make([]byte, 0, len(header)+nonceLen+len(dek)+tagLen)
	out = append(out, header...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, dek, dekAAD(credentialID, k.current))
	return out, nil
}

// UnwrapDEK decrypts a wrapped data key and reports which master key version
// wrapped it.
//
// The caller must Zero the returned key when finished.
func (k *Keyring) UnwrapDEK(wrapped []byte, credentialID string) (dek []byte, version uint16, err error) {
	if len(wrapped) < 3+nonceLen+tagLen {
		return nil, 0, ErrMalformedBlob
	}
	if wrapped[0] != blobFormatV1 {
		return nil, 0, fmt.Errorf("%w: unsupported format version %d", ErrMalformedBlob, wrapped[0])
	}
	version = binary.BigEndian.Uint16(wrapped[1:3])
	aead, ok := k.aeads[version]
	if !ok {
		return nil, version, fmt.Errorf("%w: %d", ErrUnknownKeyVersion, version)
	}

	nonce := wrapped[3 : 3+nonceLen]
	ct := wrapped[3+nonceLen:]

	dek, err = aead.Open(nil, nonce, ct, dekAAD(credentialID, version))
	if err != nil {
		return nil, version, ErrWrongKey
	}
	if len(dek) != KeyLen {
		Zero(dek)
		return nil, version, fmt.Errorf("%w: unwrapped key is %d bytes", ErrMalformedBlob, len(dek))
	}
	return dek, version, nil
}

// RewrapDEK re-encrypts a wrapped data key under the current master key. Used by
// key rotation, which never touches secret ciphertext.
//
// Returns the new blob and the version it was previously wrapped with, so the
// caller can report progress and skip rows that are already current.
func (k *Keyring) RewrapDEK(wrapped []byte, credentialID string) (rewrapped []byte, oldVersion uint16, err error) {
	dek, oldVersion, err := k.UnwrapDEK(wrapped, credentialID)
	if err != nil {
		return nil, oldVersion, err
	}
	defer Zero(dek)

	rewrapped, err = k.WrapDEK(dek, credentialID)
	if err != nil {
		return nil, oldVersion, err
	}
	return rewrapped, oldVersion, nil
}

// EncryptSecret encrypts one credential field under its data key.
//
// Layout: format(1) ‖ nonce(12) ‖ ciphertext ‖ tag. No key version is needed:
// the DEK's own blob carries it.
func EncryptSecret(dek []byte, credentialID, field string, plaintext []byte) ([]byte, error) {
	aead, err := secretAEAD(dek, credentialID, field)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}
	out := make([]byte, 0, 1+nonceLen+len(plaintext)+tagLen)
	out = append(out, blobFormatV1)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, secretAAD(credentialID, field))
	return out, nil
}

// DecryptSecret decrypts one credential field.
//
// The caller must Zero the returned plaintext when finished.
func DecryptSecret(dek []byte, credentialID, field string, blob []byte) ([]byte, error) {
	aead, err := secretAEAD(dek, credentialID, field)
	if err != nil {
		return nil, err
	}
	if len(blob) < 1+nonceLen+tagLen {
		return nil, ErrMalformedBlob
	}
	if blob[0] != blobFormatV1 {
		return nil, fmt.Errorf("%w: unsupported format version %d", ErrMalformedBlob, blob[0])
	}
	plaintext, err := aead.Open(nil, blob[1:1+nonceLen], blob[1+nonceLen:], secretAAD(credentialID, field))
	if err != nil {
		return nil, ErrWrongKey
	}
	return plaintext, nil
}

func secretAEAD(dek []byte, credentialID, field string) (cipher.AEAD, error) {
	if credentialID == "" {
		return nil, errors.New("crypto: credential id is required")
	}
	switch field {
	case FieldPassword, FieldPrivateKey, FieldPassphrase:
	default:
		return nil, fmt.Errorf("crypto: unknown secret field %q", field)
	}
	return newAEAD(dek)
}

// EncryptCanary produces the startup validation blob.
func (k *Keyring) EncryptCanary() ([]byte, error) {
	aead := k.aeads[k.current]
	if aead == nil {
		return nil, ErrUnknownKeyVersion
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}
	header := make([]byte, 3)
	header[0] = blobFormatV1
	binary.BigEndian.PutUint16(header[1:], k.current)

	out := make([]byte, 0, len(header)+nonceLen+len(canaryPlaintext)+tagLen)
	out = append(out, header...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, []byte(canaryPlaintext), []byte(aadCanary))
	return out, nil
}

// VerifyCanary checks that this keyring can decrypt the stored canary.
//
// Startup refuses to serve when this fails. Starting anyway would present an
// operator with what looks like an empty credential store and invite them to
// overwrite real data -- a far worse outcome than refusing to boot.
func (k *Keyring) VerifyCanary(blob []byte) error {
	if len(blob) < 3+nonceLen+tagLen {
		return ErrMalformedBlob
	}
	if blob[0] != blobFormatV1 {
		return fmt.Errorf("%w: unsupported format version %d", ErrMalformedBlob, blob[0])
	}
	version := binary.BigEndian.Uint16(blob[1:3])
	aead, ok := k.aeads[version]
	if !ok {
		return fmt.Errorf("%w: canary was written with key version %d", ErrUnknownKeyVersion, version)
	}
	got, err := aead.Open(nil, blob[3:3+nonceLen], blob[3+nonceLen:], []byte(aadCanary))
	if err != nil {
		return ErrWrongKey
	}
	defer Zero(got)
	if string(got) != canaryPlaintext {
		return ErrWrongKey
	}
	return nil
}

// Zero overwrites a byte slice.
//
// Best-effort by necessity: Go's garbage collector may already have copied the
// backing array, and there is no way to reach those copies. It still removes the
// long-lived copy, which is the one that ends up in a core dump or a swapped
// page. Secrets are kept in []byte rather than string for exactly this reason --
// strings are immutable and cannot be cleared at all.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func dekAAD(credentialID string, version uint16) []byte {
	return []byte(aadDEKPrefix + credentialID + "|" + strconv.FormatUint(uint64(version), 10))
}

func secretAAD(credentialID, field string) []byte {
	return []byte(aadSecretPrefix + credentialID + "|" + field)
}
