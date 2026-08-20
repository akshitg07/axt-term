package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(t *testing.T, fill byte) []byte {
	t.Helper()
	key := make([]byte, KeyLen)
	for i := range key {
		key[i] = fill + byte(i)
	}
	return key
}

func newTestKeyring(t *testing.T) *Keyring {
	t.Helper()
	k, err := NewKeyring(1, testKey(t, 0x10))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fastKDF uses the minimum permitted cost so the test suite stays quick. Real
// deployments use DefaultKDFParams.
func fastKDF(salt string) KDFParams {
	return KDFParams{Salt: []byte(salt + "----------------"), MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1}
}

func TestDEKRoundTrip(t *testing.T) {
	t.Parallel()

	k := newTestKeyring(t)
	const credID = "cred-018f-abc"

	dek, wrapped, err := k.NewDEK(credID)
	if err != nil {
		t.Fatal(err)
	}
	if len(dek) != KeyLen {
		t.Fatalf("dek length = %d, want %d", len(dek), KeyLen)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("the wrapped blob contains the plaintext data key")
	}

	got, version, err := k.UnwrapDEK(wrapped, credID)
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Errorf("version = %d, want 1", version)
	}
	if !bytes.Equal(got, dek) {
		t.Error("unwrapped data key does not match")
	}
}

func TestSecretRoundTrip(t *testing.T) {
	t.Parallel()

	k := newTestKeyring(t)
	const credID = "cred-1"
	dek, _, err := k.NewDEK(credID)
	if err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{FieldPassword, FieldPrivateKey, FieldPassphrase} {
		plaintext := []byte("value for " + field)
		blob, err := EncryptSecret(dek, credID, field, plaintext)
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		if bytes.Contains(blob, plaintext) {
			t.Fatalf("%s: plaintext is visible in the ciphertext", field)
		}
		got, err := DecryptSecret(dek, credID, field, blob)
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("%s: got %q, want %q", field, got, plaintext)
		}
	}
}

func TestEmptySecretIsEncryptable(t *testing.T) {
	t.Parallel()

	k := newTestKeyring(t)
	dek, _, err := k.NewDEK("cred-1")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := EncryptSecret(dek, "cred-1", FieldPassphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptSecret(dek, "cred-1", FieldPassphrase, blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %q, want empty", got)
	}
}

// The central property of the AAD binding: an attacker with write access to the
// database cannot move a blob to a record they are allowed to read.
func TestAADBindsDEKToItsCredential(t *testing.T) {
	t.Parallel()

	k := newTestKeyring(t)
	_, wrapped, err := k.NewDEK("cred-prod-db")
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := k.UnwrapDEK(wrapped, "cred-attacker-owned"); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("relocating a wrapped DEK to another credential must fail, got: %v", err)
	}
}

func TestAADBindsSecretToItsField(t *testing.T) {
	t.Parallel()

	k := newTestKeyring(t)
	const credID = "cred-1"
	dek, _, err := k.NewDEK(credID)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := EncryptSecret(dek, credID, FieldPassphrase, []byte("key passphrase"))
	if err != nil {
		t.Fatal(err)
	}

	// Swapping a passphrase blob into the password column must not decrypt: it
	// would otherwise let an attacker turn a key passphrase into a login
	// password on a host that accepts password auth.
	if _, err := DecryptSecret(dek, credID, FieldPassword, blob); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("field swap must fail, got: %v", err)
	}
	// And the same blob must not decrypt under a different credential id.
	if _, err := DecryptSecret(dek, "cred-2", FieldPassphrase, blob); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("credential swap must fail, got: %v", err)
	}
}

func TestTamperDetection(t *testing.T) {
	t.Parallel()

	k := newTestKeyring(t)
	const credID = "cred-1"
	dek, wrapped, err := k.NewDEK(credID)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := EncryptSecret(dek, credID, FieldPassword, []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}

	// Every byte matters: nonce, ciphertext, and tag.
	for i := range wrapped {
		mutated := append([]byte(nil), wrapped...)
		mutated[i] ^= 0x01
		if _, _, err := k.UnwrapDEK(mutated, credID); err == nil {
			t.Fatalf("flipping byte %d of the wrapped DEK went undetected", i)
		}
	}
	for i := range blob {
		mutated := append([]byte(nil), blob...)
		mutated[i] ^= 0x01
		if _, err := DecryptSecret(dek, credID, FieldPassword, mutated); err == nil {
			t.Fatalf("flipping byte %d of the secret went undetected", i)
		}
	}
}

func TestWrongMasterKeyFails(t *testing.T) {
	t.Parallel()

	right := newTestKeyring(t)
	wrong, err := NewKeyring(1, testKey(t, 0x99))
	if err != nil {
		t.Fatal(err)
	}

	_, wrapped, err := right.NewDEK("cred-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrong.UnwrapDEK(wrapped, "cred-1"); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("a different master key must fail, got: %v", err)
	}
}

func TestNoncesAreUnique(t *testing.T) {
	t.Parallel()

	k := newTestKeyring(t)
	dek, _, err := k.NewDEK("cred-1")
	if err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]bool, 256)
	plaintext := []byte("same value every time")
	for i := 0; i < 256; i++ {
		blob, err := EncryptSecret(dek, "cred-1", FieldPassword, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		nonce := string(blob[1 : 1+nonceLen])
		if seen[nonce] {
			t.Fatalf("nonce reused on iteration %d; GCM nonce reuse is catastrophic", i)
		}
		seen[nonce] = true
	}
}

// Rotation must preserve every secret while re-encrypting only the small DEK
// blobs.
func TestKeyRotation(t *testing.T) {
	t.Parallel()

	const credID = "cred-1"
	oldKey := testKey(t, 0x10)
	newKey := testKey(t, 0x40)

	k, err := NewKeyring(1, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	dek, wrapped, err := k.NewDEK(credID)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("private-key-material")
	blob, err := EncryptSecret(dek, credID, FieldPrivateKey, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Register version 2 and make it current. Version 1 stays available so rows
	// not yet rewrapped remain readable -- rotation is not atomic across a large
	// credential store.
	if err := k.AddVersion(2, newKey); err != nil {
		t.Fatal(err)
	}
	if err := k.SetCurrent(2); err != nil {
		t.Fatal(err)
	}

	if _, _, err := k.UnwrapDEK(wrapped, credID); err != nil {
		t.Fatalf("a blob wrapped with the retired key must still open during rotation: %v", err)
	}

	rewrapped, oldVersion, err := k.RewrapDEK(wrapped, credID)
	if err != nil {
		t.Fatal(err)
	}
	if oldVersion != 1 {
		t.Errorf("reported old version = %d, want 1", oldVersion)
	}

	// The rewrapped DEK must still decrypt the untouched secret ciphertext. This
	// is the whole point of the two-level design.
	rotatedDEK, version, err := k.UnwrapDEK(rewrapped, credID)
	if err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Errorf("rewrapped version = %d, want 2", version)
	}
	got, err := DecryptSecret(rotatedDEK, credID, FieldPrivateKey, blob)
	if err != nil {
		t.Fatalf("secret ciphertext must survive rotation untouched: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Error("secret changed across rotation")
	}

	// Once the retired key is gone, old blobs report a clear, actionable error
	// rather than looking like corruption.
	fresh, err := NewKeyring(2, newKey)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = fresh.UnwrapDEK(wrapped, credID)
	if !errors.Is(err, ErrUnknownKeyVersion) {
		t.Fatalf("expected ErrUnknownKeyVersion, got: %v", err)
	}
}

func TestAddVersionRejectsDuplicates(t *testing.T) {
	t.Parallel()

	k := newTestKeyring(t)
	if err := k.AddVersion(1, testKey(t, 0x77)); err == nil {
		t.Fatal("re-registering a version must fail; silently replacing a key would make existing blobs unreadable")
	}
	if err := k.SetCurrent(9); err == nil {
		t.Fatal("SetCurrent on an unregistered version must fail")
	}
}

func TestCanary(t *testing.T) {
	t.Parallel()

	k := newTestKeyring(t)
	blob, err := k.EncryptCanary()
	if err != nil {
		t.Fatal(err)
	}
	if err := k.VerifyCanary(blob); err != nil {
		t.Fatalf("the keyring that wrote the canary must verify it: %v", err)
	}

	wrong, err := NewKeyring(1, testKey(t, 0x99))
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.VerifyCanary(blob); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("a wrong master key must fail the canary, got: %v", err)
	}

	mutated := append([]byte(nil), blob...)
	mutated[len(mutated)-1] ^= 0xFF
	if err := k.VerifyCanary(mutated); err == nil {
		t.Fatal("a tampered canary must fail")
	}

	if err := k.VerifyCanary([]byte{0x01, 0x02}); !errors.Is(err, ErrMalformedBlob) {
		t.Fatal("a truncated canary must report a malformed blob")
	}
}

func TestMalformedBlobs(t *testing.T) {
	t.Parallel()

	k := newTestKeyring(t)
	dek, _, err := k.NewDEK("cred-1")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		blob []byte
	}{
		{"empty", nil},
		{"too short", []byte{0x01, 0x00}},
		{"unknown format version", append([]byte{0x02, 0x00, 0x01}, make([]byte, nonceLen+tagLen)...)},
	} {
		if _, _, err := k.UnwrapDEK(tc.blob, "cred-1"); !errors.Is(err, ErrMalformedBlob) {
			t.Errorf("UnwrapDEK(%s): expected ErrMalformedBlob, got %v", tc.name, err)
		}
	}

	if _, err := DecryptSecret(dek, "cred-1", FieldPassword, []byte{0x01}); !errors.Is(err, ErrMalformedBlob) {
		t.Error("DecryptSecret on a truncated blob must report a malformed blob")
	}
	if _, err := DecryptSecret(dek, "cred-1", "unknown_field", []byte{0x01}); err == nil {
		t.Error("an unknown field name must be rejected")
	}
	if _, err := EncryptSecret(dek, "", FieldPassword, []byte("x")); err == nil {
		t.Error("an empty credential id must be rejected")
	}
	if _, err := EncryptSecret(testKey(t, 0x01)[:16], "cred-1", FieldPassword, []byte("x")); err == nil {
		t.Error("a short data key must be rejected")
	}
}

func TestLoadMasterKeyFromBase64(t *testing.T) {
	t.Parallel()

	raw := testKey(t, 0x20)

	for _, enc := range []struct {
		name  string
		value string
	}{
		{"standard", base64.StdEncoding.EncodeToString(raw)},
		{"raw standard", base64.RawStdEncoding.EncodeToString(raw)},
		{"url safe", base64.URLEncoding.EncodeToString(raw)},
		{"surrounding whitespace", "  " + base64.StdEncoding.EncodeToString(raw) + "\n"},
	} {
		got, err := LoadMasterKey(KeySource{Base64: enc.value}, nil)
		if err != nil {
			t.Fatalf("%s: %v", enc.name, err)
		}
		if !bytes.Equal(got, raw) {
			t.Errorf("%s: decoded key does not match", enc.name)
		}
	}
}

func TestLoadMasterKeyFromFile(t *testing.T) {
	t.Parallel()

	raw := testKey(t, 0x30)
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	// A trailing newline is what `openssl rand -base64 32 > key` produces, so it
	// must be tolerated.
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadMasterKey(KeySource{File: path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Error("key from file does not match")
	}

	if _, err := LoadMasterKey(KeySource{File: filepath.Join(dir, "missing")}, nil); err == nil {
		t.Error("a missing key file must be an error")
	}
}

func TestLoadMasterKeyRejectsBadInput(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		src     KeySource
		wantSub string
	}{
		{"nothing configured", KeySource{}, "no master key configured"},
		{"two sources", KeySource{Base64: "x", Passphrase: "y"}, "more than one"},
		{"not base64", KeySource{Base64: "not!base64!"}, "not valid base64"},
		{"wrong length", KeySource{Base64: base64.StdEncoding.EncodeToString([]byte("too short"))}, "exactly 32 bytes"},
	} {
		_, err := LoadMasterKey(tc.src, nil)
		if err == nil {
			t.Errorf("%s: expected an error", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: error %q should mention %q", tc.name, err, tc.wantSub)
		}
	}

	// A passphrase without persisted parameters cannot derive a stable key, and
	// deriving an unstable one would silently orphan every stored credential.
	if _, err := LoadMasterKey(KeySource{Passphrase: "hunter2"}, nil); err == nil {
		t.Error("a passphrase without KDF parameters must be rejected")
	}
}

func TestPassphraseDerivationIsDeterministic(t *testing.T) {
	t.Parallel()

	params := fastKDF("salt-one")
	const passphrase = "correct horse battery staple"

	first, err := LoadMasterKey(KeySource{Passphrase: passphrase}, &params)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadMasterKey(KeySource{Passphrase: passphrase}, &params)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("the same passphrase and salt must derive the same key across restarts")
	}
	if len(first) != KeyLen {
		t.Errorf("derived key length = %d, want %d", len(first), KeyLen)
	}

	otherSalt := fastKDF("salt-two")
	third, err := LoadMasterKey(KeySource{Passphrase: passphrase}, &otherSalt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, third) {
		t.Fatal("a different salt must derive a different key")
	}

	different, err := LoadMasterKey(KeySource{Passphrase: "another passphrase"}, &params)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, different) {
		t.Fatal("a different passphrase must derive a different key")
	}
}

func TestKDFParamsValidation(t *testing.T) {
	t.Parallel()

	if err := (KDFParams{Salt: []byte("short"), MemoryKiB: 65536, Iterations: 3, Parallelism: 4}).Validate(); err == nil {
		t.Error("a short salt must be rejected")
	}
	if err := (KDFParams{Salt: bytes.Repeat([]byte("a"), 16), MemoryKiB: 64, Iterations: 3, Parallelism: 4}).Validate(); err == nil {
		t.Error("absurdly low memory must be rejected")
	}
	if _, err := (fastKDF("s")).Derive(""); err == nil {
		t.Error("an empty passphrase must be rejected")
	}

	params, err := DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if err := params.Validate(); err != nil {
		t.Errorf("the defaults must validate: %v", err)
	}
	if len(params.Salt) < 16 {
		t.Errorf("default salt is %d bytes, want at least 16", len(params.Salt))
	}

	other, err := DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(params.Salt, other.Salt) {
		t.Error("each call must generate a fresh salt")
	}
}

func TestGenerateMasterKeyIsLoadable(t *testing.T) {
	t.Parallel()

	encoded, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := LoadMasterKey(KeySource{Base64: encoded}, nil)
	if err != nil {
		t.Fatalf("a generated key must load: %v", err)
	}
	if len(key) != KeyLen {
		t.Errorf("length = %d, want %d", len(key), KeyLen)
	}

	// Two calls must differ.
	other, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if encoded == other {
		t.Error("generated keys must be random")
	}
}

func TestNewKeyringValidation(t *testing.T) {
	t.Parallel()

	if _, err := NewKeyring(0, testKey(t, 0x01)); err == nil {
		t.Error("version 0 must be rejected; versions start at 1")
	}
	if _, err := NewKeyring(1, []byte("too short")); err == nil {
		t.Error("a short master key must be rejected")
	}
}

func TestZero(t *testing.T) {
	t.Parallel()

	b := []byte("sensitive")
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %d, want 0", i, v)
		}
	}
	Zero(nil) // must not panic
}

func TestNewDEKRequiresCredentialID(t *testing.T) {
	t.Parallel()

	if _, _, err := newTestKeyring(t).NewDEK(""); err == nil {
		t.Error("an empty credential id must be rejected: the AAD binding depends on it")
	}
}
