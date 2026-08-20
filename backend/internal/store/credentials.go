package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// The store persists ciphertext only. Encryption and decryption belong to the
// credentials service, which holds the keyring; this layer never sees a
// plaintext secret and has no code path that could log one.

const credentialColumns = `id, name, kind, provider, external_ref, username, domain,
	key_type, key_fingerprint, key_comment, dek_wrapped, key_version, notes,
	created_by, created_at, updated_at, last_used_at`

func scanCredential(row rowScanner) (*Credential, error) {
	var (
		c           Credential
		dek         []byte
		createdBy   sql.NullString
		lastUsedAt  sql.NullString
		createdAt   string
		updatedAt   string
		externalRef sql.NullString
	)
	err := row.Scan(&c.ID, &c.Name, &c.Kind, &c.Provider, &externalRef, &c.Username, &c.Domain,
		&c.KeyType, &c.KeyFingerprint, &c.KeyComment, &dek, &c.KeyVersion, &c.Notes,
		&createdBy, &createdAt, &updatedAt, &lastUsedAt)
	if err != nil {
		return nil, err
	}
	c.ExternalRef = str(externalRef)
	c.DEKWrapped = dek
	c.CreatedBy = str(createdBy)
	c.CreatedAt = parseTime(createdAt)
	c.UpdatedAt = parseTime(updatedAt)
	c.LastUsedAt = timePtr(lastUsedAt)
	return &c, nil
}

// ListCredentials returns credential metadata with which secret fields are set
// and how many hosts reference each.
//
// The "which fields are set" columns are how the UI shows "password configured"
// without any endpoint ever reading a secret.
func (s *Store) ListCredentials(ctx context.Context) ([]*Credential, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT `+credentialColumns+` FROM credentials ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*Credential{}
	byID := make(map[string]*Credential)
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		byID[c.ID] = c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	if err := s.attachSecretPresence(ctx, byID); err != nil {
		return nil, err
	}
	return out, s.attachCredentialUsage(ctx, byID)
}

func (s *Store) attachSecretPresence(ctx context.Context, byID map[string]*Credential) error {
	rows, err := s.read.QueryContext(ctx, `SELECT credential_id, field FROM credential_secrets`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var id, field string
		if err := rows.Scan(&id, &field); err != nil {
			return err
		}
		c, ok := byID[id]
		if !ok {
			continue
		}
		switch field {
		case "password":
			c.HasPassword = true
		case "private_key":
			c.HasPrivateKey = true
		case "passphrase":
			c.HasPassphrase = true
		}
	}
	return rows.Err()
}

func (s *Store) attachCredentialUsage(ctx context.Context, byID map[string]*Credential) error {
	rows, err := s.read.QueryContext(ctx, `
		SELECT credential_id, COUNT(*) FROM hosts
		WHERE credential_id IS NOT NULL GROUP BY credential_id`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			id string
			n  int
		)
		if err := rows.Scan(&id, &n); err != nil {
			return err
		}
		if c, ok := byID[id]; ok {
			c.InUseByCount = n
		}
	}
	return rows.Err()
}

// CredentialByID loads one credential's metadata, including its wrapped data key
// so the service can decrypt secrets.
func (s *Store) CredentialByID(ctx context.Context, id string) (*Credential, error) {
	c, err := scanCredential(s.read.QueryRowContext(ctx,
		`SELECT `+credentialColumns+` FROM credentials WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	byID := map[string]*Credential{c.ID: c}
	if err := s.attachSecretPresence(ctx, byID); err != nil {
		return nil, err
	}
	if err := s.attachCredentialUsage(ctx, byID); err != nil {
		return nil, err
	}
	return c, nil
}

// CreateCredential inserts a credential and its encrypted fields.
//
// secrets maps field name to ciphertext. Passing plaintext here would be a bug
// in the caller; the store cannot tell the difference, which is why encryption
// lives one layer up where the keyring is.
func (s *Store) CreateCredential(ctx context.Context, c *Credential, secrets map[string][]byte) error {
	now := s.now()
	c.CreatedAt, c.UpdatedAt = now, now

	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO credentials (`+credentialColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			c.ID, c.Name, string(c.Kind), string(c.Provider), c.ExternalRef, c.Username, c.Domain,
			c.KeyType, c.KeyFingerprint, c.KeyComment, c.DEKWrapped, c.KeyVersion, c.Notes,
			nullIfEmpty(c.CreatedBy), fmtTime(c.CreatedAt), fmtTime(c.UpdatedAt))
		if err != nil {
			return mapWriteError(err)
		}
		return putSecretsTx(ctx, tx, c.ID, secrets, now)
	})
}

// UpdateCredential replaces metadata and, for any field present in secrets, the
// ciphertext.
//
// A field absent from the map is left untouched. That is what lets the edit form
// omit a password the user did not retype without clearing the stored one.
func (s *Store) UpdateCredential(ctx context.Context, c *Credential, secrets map[string][]byte) error {
	now := s.now()
	c.UpdatedAt = now

	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE credentials SET name = ?, kind = ?, provider = ?, external_ref = ?,
				username = ?, domain = ?, key_type = ?, key_fingerprint = ?, key_comment = ?,
				notes = ?, updated_at = ?
			WHERE id = ?`,
			c.Name, string(c.Kind), string(c.Provider), c.ExternalRef, c.Username, c.Domain,
			c.KeyType, c.KeyFingerprint, c.KeyComment, c.Notes, fmtTime(now), c.ID)
		if err := affected(res, err); err != nil {
			return err
		}
		return putSecretsTx(ctx, tx, c.ID, secrets, now)
	})
}

func putSecretsTx(ctx context.Context, tx *sql.Tx, credentialID string, secrets map[string][]byte, now time.Time) error {
	for field, ciphertext := range secrets {
		switch field {
		case "password", "private_key", "passphrase":
		default:
			return fmt.Errorf("store: unknown credential field %q", field)
		}
		if len(ciphertext) == 0 {
			// An explicitly empty value clears the field.
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM credential_secrets WHERE credential_id = ? AND field = ?`,
				credentialID, field); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO credential_secrets (credential_id, field, ciphertext, updated_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(credential_id, field) DO UPDATE SET
				ciphertext = excluded.ciphertext, updated_at = excluded.updated_at`,
			credentialID, field, ciphertext, fmtTime(now)); err != nil {
			return mapWriteError(err)
		}
	}
	return nil
}

// CredentialSecret returns the ciphertext for one field.
func (s *Store) CredentialSecret(ctx context.Context, credentialID, field string) ([]byte, error) {
	var ciphertext []byte
	err := s.read.QueryRowContext(ctx,
		`SELECT ciphertext FROM credential_secrets WHERE credential_id = ? AND field = ?`,
		credentialID, field).Scan(&ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// DeleteCredential removes a credential. Hosts referencing it fall back to
// prompting, because the foreign key is ON DELETE SET NULL -- silently breaking
// a host is better than refusing to delete a compromised credential.
func (s *Store) DeleteCredential(ctx context.Context, id string) error {
	res, err := s.write.ExecContext(ctx, `DELETE FROM credentials WHERE id = ?`, id)
	return affected(res, err)
}

// TouchCredentialUsed records that a credential was used to authenticate.
func (s *Store) TouchCredentialUsed(ctx context.Context, id string) error {
	_, err := s.write.ExecContext(ctx,
		`UPDATE credentials SET last_used_at = ? WHERE id = ?`, fmtTime(s.now()), id)
	return err
}

// CredentialDEK is the minimum needed to rewrap a data key during rotation.
type CredentialDEK struct {
	ID         string
	Name       string
	DEKWrapped []byte
	KeyVersion int
}

// CredentialsForRotation lists every credential holding a locally wrapped data
// key, oldest key version first.
func (s *Store) CredentialsForRotation(ctx context.Context) ([]CredentialDEK, error) {
	rows, err := s.read.QueryContext(ctx, `
		SELECT id, name, dek_wrapped, key_version FROM credentials
		WHERE dek_wrapped IS NOT NULL ORDER BY key_version, name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []CredentialDEK{}
	for rows.Next() {
		var c CredentialDEK
		if err := rows.Scan(&c.ID, &c.Name, &c.DEKWrapped, &c.KeyVersion); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateCredentialDEK stores a rewrapped data key. Secret ciphertext is
// untouched, which is what makes rotation fast and low-risk.
func (s *Store) UpdateCredentialDEK(ctx context.Context, id string, wrapped []byte, keyVersion int) error {
	res, err := s.write.ExecContext(ctx,
		`UPDATE credentials SET dek_wrapped = ?, key_version = ?, updated_at = ? WHERE id = ?`,
		wrapped, keyVersion, fmtTime(s.now()), id)
	return affected(res, err)
}

// -------------------------------------------------------------- crypto keys ---

// CryptoKeyByVersion loads one master key record.
func (s *Store) CryptoKeyByVersion(ctx context.Context, version int) (*CryptoKey, error) {
	var (
		k         CryptoKey
		kdf       sql.NullString
		salt      []byte
		params    sql.NullString
		createdAt string
		retiredAt sql.NullString
	)
	err := s.read.QueryRowContext(ctx, `
		SELECT version, algo, kdf, kdf_salt, kdf_params, created_at, retired_at
		FROM crypto_keys WHERE version = ?`, version).
		Scan(&k.Version, &k.Algo, &kdf, &salt, &params, &createdAt, &retiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	k.KDF = str(kdf)
	k.KDFSalt = salt
	k.KDFParams = str(params)
	k.CreatedAt = parseTime(createdAt)
	k.RetiredAt = timePtr(retiredAt)
	return &k, nil
}

// CurrentCryptoKey returns the highest non-retired key version.
func (s *Store) CurrentCryptoKey(ctx context.Context) (*CryptoKey, error) {
	var version int
	err := s.read.QueryRowContext(ctx,
		`SELECT version FROM crypto_keys WHERE retired_at IS NULL ORDER BY version DESC LIMIT 1`).
		Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.CryptoKeyByVersion(ctx, version)
}

// CreateCryptoKey records a new master key version.
func (s *Store) CreateCryptoKey(ctx context.Context, k *CryptoKey) error {
	if k.CreatedAt.IsZero() {
		k.CreatedAt = s.now()
	}
	_, err := s.write.ExecContext(ctx, `
		INSERT INTO crypto_keys (version, algo, kdf, kdf_salt, kdf_params, created_at, retired_at)
		VALUES (?, ?, ?, ?, ?, ?, NULL)`,
		k.Version, k.Algo, nullIfEmpty(k.KDF), k.KDFSalt, nullIfEmpty(k.KDFParams),
		fmtTime(k.CreatedAt))
	return mapWriteError(err)
}

// RetireCryptoKey marks a key version as no longer current.
func (s *Store) RetireCryptoKey(ctx context.Context, version int) error {
	res, err := s.write.ExecContext(ctx,
		`UPDATE crypto_keys SET retired_at = ? WHERE version = ? AND retired_at IS NULL`,
		fmtTime(s.now()), version)
	return affected(res, err)
}

// NextCryptoKeyVersion returns the version a new key should take.
func (s *Store) NextCryptoKeyVersion(ctx context.Context) (int, error) {
	var maxVersion sql.NullInt64
	if err := s.read.QueryRowContext(ctx, `SELECT MAX(version) FROM crypto_keys`).Scan(&maxVersion); err != nil {
		return 0, err
	}
	if !maxVersion.Valid {
		return 1, nil
	}
	return int(maxVersion.Int64) + 1, nil
}
