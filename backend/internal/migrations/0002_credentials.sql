-- 0002: credential storage.
--
-- Secrets live in their own table so a SELECT for a list view cannot load
-- ciphertext by accident, so a Vault-backed credential can carry no local
-- ciphertext at all, and so per-field rotation is auditable.

CREATE TABLE crypto_keys (
    version    INTEGER PRIMARY KEY,
    algo       TEXT NOT NULL DEFAULT 'aes-256-gcm',
    kdf        TEXT,
    kdf_salt   BLOB,
    kdf_params TEXT,
    created_at TEXT NOT NULL,
    retired_at TEXT
);

CREATE TABLE credentials (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE COLLATE NOCASE,
    kind            TEXT NOT NULL CHECK (kind IN ('password', 'ssh_key', 'ssh_agent', 'rdp_password')),
    provider        TEXT NOT NULL DEFAULT 'local'
                      CHECK (provider IN ('local', 'vault', 'bitwarden', 'onepassword', 'env')),
    external_ref    TEXT NOT NULL DEFAULT '',
    username        TEXT NOT NULL DEFAULT '',
    domain          TEXT NOT NULL DEFAULT '',
    key_type        TEXT NOT NULL DEFAULT '',
    key_fingerprint TEXT NOT NULL DEFAULT '',
    key_comment     TEXT NOT NULL DEFAULT '',
    dek_wrapped     BLOB,
    key_version     INTEGER NOT NULL DEFAULT 1,
    notes           TEXT NOT NULL DEFAULT '',
    created_by      TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_used_at    TEXT
);

CREATE TABLE credential_secrets (
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    field         TEXT NOT NULL CHECK (field IN ('password', 'private_key', 'passphrase')),
    ciphertext    BLOB NOT NULL,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (credential_id, field)
);
