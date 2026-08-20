// Package credentials owns credential profiles and is the only place plaintext
// secrets exist in this application.
//
// The store persists ciphertext, the crypto package encrypts, and this package
// orchestrates. Nothing above it ever receives a secret: the API's response type
// has no field for one, and Resolve -- the single method that decrypts -- returns
// a value the caller is required to Zero and is only ever called by the SSH and
// RDP engines.
package credentials

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/axt-term/axt-term/backend/internal/crypto"
	"github.com/axt-term/axt-term/backend/internal/sshx"
	"github.com/axt-term/axt-term/backend/internal/store"
	"github.com/axt-term/axt-term/backend/internal/validate"
	"github.com/google/uuid"
)

// Errors returned by the service.
var (
	ErrProviderUnsupported = errors.New("credentials: this provider is not implemented in this build")
	ErrNoSecret            = errors.New("credentials: no secret is stored for this field")
	ErrInUse               = errors.New("credentials: still referenced by hosts")
)

// Service manages credential profiles.
type Service struct {
	store   *store.Store
	keyring *crypto.Keyring
	log     *slog.Logger
}

// NewService wires the service.
func NewService(st *store.Store, keyring *crypto.Keyring, log *slog.Logger) *Service {
	return &Service{store: st, keyring: keyring, log: log}
}

// CreateInput carries a new credential. Secret fields are write-only: they enter
// here and are never returned by any endpoint.
type CreateInput struct {
	Name       string
	Kind       store.CredentialKind
	Provider   store.CredentialProvider
	Username   string
	Domain     string
	Notes      string
	Password   string
	PrivateKey string
	Passphrase string
	ActorID    string
}

// Validate checks the input.
func (in CreateInput) Validate() *validate.Errors {
	v := &validate.Errors{}
	v.Check("name", validate.Name(in.Name, 120))
	if !in.Kind.Valid() {
		v.Add("kind", "must be password, ssh_key, ssh_agent, or rdp_password")
	}
	if in.Provider != "" && !in.Provider.Implemented() {
		v.Add("provider", "only the local provider is implemented in this build")
	}
	v.Check("username", validate.Username(in.Username))

	switch in.Kind {
	case store.CredPassword, store.CredRDPPassword:
		if in.Password == "" {
			v.Add("password", "required for this credential kind")
		}
		if in.PrivateKey != "" {
			v.Add("private_key", "not applicable to a password credential")
		}
	case store.CredSSHKey:
		if in.PrivateKey == "" {
			v.Add("private_key", "required for an SSH key credential")
		}
	case store.CredSSHAgent:
		if in.Password != "" || in.PrivateKey != "" {
			v.Add("kind", "an agent credential holds no secret material")
		}
	}
	return v
}

// Create stores a new credential.
func (s *Service) Create(ctx context.Context, in CreateInput) (*store.Credential, error) {
	if v := in.Validate(); v.Any() {
		return nil, v
	}
	provider := in.Provider
	if provider == "" {
		provider = store.ProviderLocal
	}
	if !provider.Implemented() {
		return nil, ErrProviderUnsupported
	}

	cred := &store.Credential{
		ID:         uuid.NewString(),
		Name:       strings.TrimSpace(in.Name),
		Kind:       in.Kind,
		Provider:   provider,
		Username:   in.Username,
		Domain:     in.Domain,
		Notes:      in.Notes,
		KeyVersion: int(s.keyring.CurrentVersion()),
		CreatedBy:  in.ActorID,
	}

	// The public half of an SSH key is derived and stored so the UI can identify
	// the key by fingerprint. Showing a fingerprint rather than a key is what
	// lets an operator confirm they attached the right credential without the
	// application ever needing to display secret material.
	if in.PrivateKey != "" {
		keyType, fingerprint, comment, err := sshx.PublicKeyFingerprint(
			[]byte(in.PrivateKey), []byte(in.Passphrase))
		if err != nil {
			v := &validate.Errors{}
			v.Add("private_key", err.Error())
			return nil, v
		}
		cred.KeyType = keyType
		cred.KeyFingerprint = fingerprint
		cred.KeyComment = comment
	}

	dek, wrapped, err := s.keyring.NewDEK(cred.ID)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(dek)
	cred.DEKWrapped = wrapped

	secrets, err := encryptFields(dek, cred.ID, map[string]string{
		crypto.FieldPassword:   in.Password,
		crypto.FieldPrivateKey: in.PrivateKey,
		crypto.FieldPassphrase: in.Passphrase,
	})
	if err != nil {
		return nil, err
	}

	if err := s.store.CreateCredential(ctx, cred, secrets); err != nil {
		return nil, err
	}
	return s.store.CredentialByID(ctx, cred.ID)
}

// UpdateInput carries changes. A nil secret pointer means "leave unchanged"; a
// pointer to an empty string means "clear".
//
// That distinction is what lets an edit form omit a password the user did not
// retype without silently deleting the stored one -- a mistake that would break
// every host referencing the credential.
type UpdateInput struct {
	Name       *string
	Username   *string
	Domain     *string
	Notes      *string
	Password   *string
	PrivateKey *string
	Passphrase *string
}

// Update modifies a credential.
func (s *Service) Update(ctx context.Context, id string, in UpdateInput) (*store.Credential, error) {
	cred, err := s.store.CredentialByID(ctx, id)
	if err != nil {
		return nil, err
	}

	v := &validate.Errors{}
	if in.Name != nil {
		v.Check("name", validate.Name(*in.Name, 120))
		cred.Name = strings.TrimSpace(*in.Name)
	}
	if in.Username != nil {
		v.Check("username", validate.Username(*in.Username))
		cred.Username = *in.Username
	}
	if in.Domain != nil {
		cred.Domain = *in.Domain
	}
	if in.Notes != nil {
		cred.Notes = *in.Notes
	}
	if v.Any() {
		return nil, v
	}

	secrets := map[string][]byte{}
	if in.Password != nil || in.PrivateKey != nil || in.Passphrase != nil {
		if len(cred.DEKWrapped) == 0 {
			return nil, errors.New("credentials: this credential has no data key; recreate it")
		}
		dek, _, err := s.keyring.UnwrapDEK(cred.DEKWrapped, cred.ID)
		if err != nil {
			return nil, err
		}
		defer crypto.Zero(dek)

		plain := map[string]string{}
		if in.Password != nil {
			plain[crypto.FieldPassword] = *in.Password
		}
		if in.PrivateKey != nil {
			plain[crypto.FieldPrivateKey] = *in.PrivateKey
		}
		if in.Passphrase != nil {
			plain[crypto.FieldPassphrase] = *in.Passphrase
		}

		secrets, err = encryptFields(dek, cred.ID, plain)
		if err != nil {
			return nil, err
		}

		// Re-derive the fingerprint whenever the key or its passphrase changes,
		// so the displayed identity never describes a key that is no longer there.
		if in.PrivateKey != nil && *in.PrivateKey != "" {
			passphrase := ""
			if in.Passphrase != nil {
				passphrase = *in.Passphrase
			}
			keyType, fingerprint, comment, ferr := sshx.PublicKeyFingerprint(
				[]byte(*in.PrivateKey), []byte(passphrase))
			if ferr != nil {
				ve := &validate.Errors{}
				ve.Add("private_key", ferr.Error())
				return nil, ve
			}
			cred.KeyType, cred.KeyFingerprint, cred.KeyComment = keyType, fingerprint, comment
		}
		if in.PrivateKey != nil && *in.PrivateKey == "" {
			cred.KeyType, cred.KeyFingerprint, cred.KeyComment = "", "", ""
		}
	}

	if err := s.store.UpdateCredential(ctx, cred, secrets); err != nil {
		return nil, err
	}
	return s.store.CredentialByID(ctx, id)
}

// encryptFields encrypts the non-nil fields under the credential's data key.
func encryptFields(dek []byte, credentialID string, plain map[string]string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(plain))
	for field, value := range plain {
		if value == "" {
			// An empty value clears the field. The store deletes the row rather
			// than storing an encrypted empty string, so "has_password" stays
			// accurate.
			out[field] = nil
			continue
		}
		ciphertext, err := crypto.EncryptSecret(dek, credentialID, field, []byte(value))
		if err != nil {
			return nil, err
		}
		out[field] = ciphertext
	}
	return out, nil
}

// List returns credential metadata.
func (s *Service) List(ctx context.Context) ([]*store.Credential, error) {
	return s.store.ListCredentials(ctx)
}

// Get returns one credential's metadata.
func (s *Service) Get(ctx context.Context, id string) (*store.Credential, error) {
	return s.store.CredentialByID(ctx, id)
}

// Delete removes a credential.
//
// Hosts referencing it are not deleted; the foreign key sets their reference to
// NULL and they fall back to prompting. Refusing to delete a credential that
// might be compromised because it is in use would be the wrong trade-off.
func (s *Service) Delete(ctx context.Context, id string, force bool) error {
	hosts, err := s.store.HostsReferencingCredential(ctx, id)
	if err != nil {
		return err
	}
	if len(hosts) > 0 && !force {
		names := make([]string, 0, len(hosts))
		for _, h := range hosts {
			names = append(names, h.Name)
		}
		return fmt.Errorf("%w: %s", ErrInUse, strings.Join(names, ", "))
	}
	return s.store.DeleteCredential(ctx, id)
}

// Resolved is decrypted credential material.
//
// The caller must call Zero when finished. Every caller is an engine that hands
// these bytes straight to a handshake.
type Resolved struct {
	Kind       store.CredentialKind
	Username   string
	Domain     string
	Password   []byte
	PrivateKey []byte
	Passphrase []byte
}

// Zero wipes the secret material.
func (r *Resolved) Zero() {
	if r == nil {
		return
	}
	crypto.Zero(r.Password)
	crypto.Zero(r.PrivateKey)
	crypto.Zero(r.Passphrase)
}

// Resolve decrypts a credential for use by a protocol engine.
//
// This is the only path from ciphertext to plaintext in the application. It is
// called by the SSH chain resolver and the RDP handshake, both of which run
// entirely server-side.
func (s *Service) Resolve(ctx context.Context, credentialID string) (*Resolved, error) {
	cred, err := s.store.CredentialByID(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	if !cred.Provider.Implemented() {
		return nil, fmt.Errorf("%w: %s", ErrProviderUnsupported, cred.Provider)
	}

	out := &Resolved{
		Kind:     cred.Kind,
		Username: cred.Username,
		Domain:   cred.Domain,
	}
	if cred.Kind == store.CredSSHAgent {
		return out, nil
	}
	if len(cred.DEKWrapped) == 0 {
		return out, nil
	}

	dek, _, err := s.keyring.UnwrapDEK(cred.DEKWrapped, cred.ID)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(dek)

	for _, field := range []string{crypto.FieldPassword, crypto.FieldPrivateKey, crypto.FieldPassphrase} {
		ciphertext, err := s.store.CredentialSecret(ctx, cred.ID, field)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			out.Zero()
			return nil, err
		}
		plaintext, err := crypto.DecryptSecret(dek, cred.ID, field, ciphertext)
		if err != nil {
			out.Zero()
			return nil, fmt.Errorf("credentials: %s for %q could not be decrypted: %w", field, cred.Name, err)
		}
		switch field {
		case crypto.FieldPassword:
			out.Password = plaintext
		case crypto.FieldPrivateKey:
			out.PrivateKey = plaintext
		case crypto.FieldPassphrase:
			out.Passphrase = plaintext
		}
	}

	if err := s.store.TouchCredentialUsed(ctx, cred.ID); err != nil {
		s.log.WarnContext(ctx, "could not record credential use", slog.Any("error", err))
	}
	return out, nil
}

// InitCanary writes the startup validation blob if it is missing.
func (s *Service) InitCanary(ctx context.Context) error {
	if _, err := s.store.SettingBytes(ctx, store.SettingCanary); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	blob, err := s.keyring.EncryptCanary()
	if err != nil {
		return err
	}
	return s.store.SetSettingBytes(ctx, store.SettingCanary, blob, "")
}

// VerifyCanary confirms the configured master key matches the stored data.
//
// Startup refuses to serve when this fails. Starting anyway would present an
// operator with what looks like an empty credential store and invite them to
// recreate credentials over data that is still there -- a far worse outcome than
// refusing to boot.
func (s *Service) VerifyCanary(ctx context.Context) error {
	blob, err := s.store.SettingBytes(ctx, store.SettingCanary)
	if errors.Is(err, store.ErrNotFound) {
		return s.InitCanary(ctx)
	}
	if err != nil {
		return err
	}
	if err := s.keyring.VerifyCanary(blob); err != nil {
		return fmt.Errorf(
			"the configured master key does not match this database (%w). "+
				"Check AXT_MASTER_KEY / AXT_MASTER_KEY_FILE / AXT_MASTER_PASSPHRASE. "+
				"Starting with the wrong key would show an empty credential store while the real data is still encrypted", err)
	}
	return nil
}

// RotateMasterKey rewraps every data key under a new master key.
//
// Secret ciphertext is untouched: only the small wrapped data keys change, which
// is what makes rotation fast and its failure window tiny. The old key must still
// be registered in the keyring so rows not yet rewrapped stay readable.
func (s *Service) RotateMasterKey(ctx context.Context) (rewrapped int, err error) {
	creds, err := s.store.CredentialsForRotation(ctx)
	if err != nil {
		return 0, err
	}
	current := int(s.keyring.CurrentVersion())

	for _, c := range creds {
		if c.KeyVersion == current {
			continue
		}
		wrapped, oldVersion, err := s.keyring.RewrapDEK(c.DEKWrapped, c.ID)
		if err != nil {
			return rewrapped, fmt.Errorf("credentials: rewrap %q (key version %d): %w", c.Name, oldVersion, err)
		}
		if err := s.store.UpdateCredentialDEK(ctx, c.ID, wrapped, current); err != nil {
			return rewrapped, fmt.Errorf("credentials: store rewrapped key for %q: %w", c.Name, err)
		}
		rewrapped++
	}

	// The canary is rewritten last, so a rotation interrupted partway leaves the
	// old canary in place and the old key still validates on restart.
	blob, err := s.keyring.EncryptCanary()
	if err != nil {
		return rewrapped, err
	}
	if err := s.store.SetSettingBytes(ctx, store.SettingCanary, blob, ""); err != nil {
		return rewrapped, err
	}
	return rewrapped, nil
}
