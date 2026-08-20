# 4. Data Model

SQLite dialect, portable SQL. Conventions used throughout:

- **Primary keys** are `TEXT` UUIDv4 (`id`). Stable across export/import and safe to expose.
- **Timestamps** are `TEXT` RFC 3339 UTC (`2026-08-19T10:22:31Z`) — human-readable in a
  `sqlite3` shell, sortable lexicographically, unambiguous in backups.
- **Booleans** are `INTEGER` 0/1 with `CHECK` constraints.
- **Enums** are `TEXT` with `CHECK (col IN (...))` so bad data cannot enter, and new values
  arrive by migration rather than silently.
- **Encrypted values** are `BLOB` in the form `version(1) ‖ nonce(12) ‖ ciphertext ‖ tag(16)`.
- Foreign keys are declared with explicit `ON DELETE` behaviour — never left to chance.

Phase 1 creates the identity, inventory, credential, snippet, session-history, transfer,
audit, and settings tables. Later-phase tables are documented here so the schema evolves
by addition rather than redesign, and are marked with the phase that creates them.

## 4.1 Entity relationships

```
users ──┬──< user_roles >── roles ──< role_permissions >── permissions
        ├──< auth_sessions
        ├──< user_settings
        ├──< workspaces
        ├──< session_records >── hosts
        └──< transfers >──────── hosts

folders ──< folders (nested, parent_id)
folders ──< hosts

hosts ──┬──> credentials ──< credential_secrets
        ├──> hosts (jump_host_id, self-reference)
        ├──< host_tags >── tags
        ├──── host_health (1:1)
        ├──< host_keys
        ├──< tunnels
        └──< session_records

snippet_folders ──< snippet_folders (nested)
snippet_folders ──< snippets

exec_jobs ──< exec_job_hosts >── hosts          (Phase 2)
discovery_scans ──< discovered_hosts            (Phase 3)
audit_events ──> users, hosts (soft references + snapshots)
```

## 4.2 Identity and access

```sql
CREATE TABLE users (
    id                   TEXT PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email                TEXT,
    display_name         TEXT NOT NULL DEFAULT '',
    password_hash        TEXT NOT NULL,              -- argon2id encoded string
    totp_secret_enc      BLOB,                       -- NULL until 2FA enrolled
    is_active            INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
    must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0,1)),
    failed_login_count   INTEGER NOT NULL DEFAULT 0,
    locked_until         TEXT,
    last_login_at        TEXT,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);

CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    is_builtin  INTEGER NOT NULL DEFAULT 0 CHECK (is_builtin IN (0,1))
);

CREATE TABLE permissions (
    key         TEXT PRIMARY KEY,       -- 'host.read', 'session.ssh', 'file.write', …
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE role_permissions (
    role_id        TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_key TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_key)
);

CREATE TABLE user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE auth_sessions (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    BLOB NOT NULL UNIQUE,   -- SHA-256 of the cookie value; the token itself is never stored
    csrf_hash     BLOB NOT NULL,
    user_agent    TEXT NOT NULL DEFAULT '',
    ip            TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    revoked_at    TEXT
);
CREATE INDEX idx_auth_sessions_user    ON auth_sessions(user_id);
CREATE INDEX idx_auth_sessions_expires ON auth_sessions(expires_at);
```

Built-in roles seeded by migration, and the permission set is enforced from Phase 1 so
RBAC is load-bearing rather than a later retrofit:

| Role | Permissions |
| --- | --- |
| `admin` | everything, including `admin.users`, `admin.audit`, `admin.settings`, `credential.write` |
| `operator` | `host.*`, `session.*`, `file.*`, `snippet.*`, `transfer.*`, `credential.use` (use but not read/export) |
| `viewer` | `host.read`, `snippet.read`, `session.ssh` (read-only shell is still a shell — deployments that need true read-only restrict at the target, and the UI says so) |

`credential.use` versus `credential.read` is the important distinction: an operator can
connect with a credential without being able to retrieve or export its secret.

## 4.3 Inventory

```sql
CREATE TABLE folders (
    id         TEXT PRIMARY KEY,
    parent_id  TEXT REFERENCES folders(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    icon       TEXT,
    color      TEXT,                                  -- '#22d3ee'
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (parent_id, name)
);

CREATE TABLE hosts (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    hostname                TEXT NOT NULL,            -- DNS name or IP
    port                    INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol                TEXT NOT NULL CHECK (protocol IN ('ssh','sftp','rdp','vnc','telnet','serial','winrm')),
    folder_id               TEXT REFERENCES folders(id) ON DELETE SET NULL,
    username                TEXT,                     -- overrides credential's username when set
    auth_method             TEXT NOT NULL DEFAULT 'credential'
                              CHECK (auth_method IN ('credential','agent','password_prompt','key_prompt')),
    credential_id           TEXT REFERENCES credentials(id) ON DELETE SET NULL,
    jump_host_id            TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    os_family               TEXT CHECK (os_family IN ('linux','windows','bsd','macos','network','unknown')),
    color                   TEXT,
    icon                    TEXT,
    notes                   TEXT NOT NULL DEFAULT '',
    is_favorite             INTEGER NOT NULL DEFAULT 0 CHECK (is_favorite IN (0,1)),
    sort_order              INTEGER NOT NULL DEFAULT 0,
    health_check_enabled    INTEGER NOT NULL DEFAULT 0 CHECK (health_check_enabled IN (0,1)),
    health_check_interval_s INTEGER NOT NULL DEFAULT 300 CHECK (health_check_interval_s >= 30),
    command_logging         TEXT NOT NULL DEFAULT 'inherit'
                              CHECK (command_logging IN ('inherit','off','commands','full')),
    rdp_options_json        TEXT,                     -- domain, security mode, redirection flags
    created_by              TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL
);
CREATE INDEX idx_hosts_folder   ON hosts(folder_id);
CREATE INDEX idx_hosts_favorite ON hosts(is_favorite) WHERE is_favorite = 1;
CREATE INDEX idx_hosts_name     ON hosts(name COLLATE NOCASE);

CREATE TABLE tags (
    id    TEXT PRIMARY KEY,
    name  TEXT NOT NULL UNIQUE COLLATE NOCASE,
    color TEXT
);

CREATE TABLE host_tags (
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    tag_id  TEXT NOT NULL REFERENCES tags(id)  ON DELETE CASCADE,
    PRIMARY KEY (host_id, tag_id)
);
CREATE INDEX idx_host_tags_tag ON host_tags(tag_id);

CREATE TABLE host_health (
    host_id    TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    status     TEXT NOT NULL CHECK (status IN ('online','slow','offline','unknown')),
    latency_ms INTEGER,
    checked_at TEXT NOT NULL,
    error      TEXT
);

-- SSH host key trust store. Keyed by hostname:port, not host id, so the same
-- machine reached through two host entries shares one trust decision.
CREATE TABLE host_keys (
    id                 TEXT PRIMARY KEY,
    hostname           TEXT NOT NULL,
    port               INTEGER NOT NULL,
    key_type           TEXT NOT NULL,               -- ssh-ed25519, rsa-sha2-512, …
    fingerprint_sha256 TEXT NOT NULL,               -- 'SHA256:base64'
    public_key         BLOB NOT NULL,               -- wire format
    first_seen_at      TEXT NOT NULL,
    last_seen_at       TEXT NOT NULL,
    trusted_by         TEXT REFERENCES users(id) ON DELETE SET NULL,
    revoked_at         TEXT,
    UNIQUE (hostname, port, key_type)
);
```

`hosts.protocol` accepts future protocol values from the start: adding VNC means writing an
engine, not migrating the inventory.

## 4.4 Credentials

```sql
CREATE TABLE credentials (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL CHECK (kind IN ('password','ssh_key','ssh_agent','rdp_password')),
    provider        TEXT NOT NULL DEFAULT 'local'
                      CHECK (provider IN ('local','vault','bitwarden','onepassword','env')),
    external_ref    TEXT,                    -- e.g. 'secret/data/infra/prod#private_key'
    username        TEXT,
    domain          TEXT,                    -- Windows/RDP
    key_type        TEXT,                    -- ed25519, rsa, ecdsa
    key_fingerprint TEXT,                    -- SHA256:… shown in the UI instead of the key
    key_comment     TEXT,
    dek_wrapped     BLOB,                    -- data key wrapped by the master KEK
    key_version     INTEGER NOT NULL DEFAULT 1 REFERENCES crypto_keys(version),
    notes           TEXT NOT NULL DEFAULT '',
    created_by      TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_used_at    TEXT
);

CREATE TABLE credential_secrets (
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    field         TEXT NOT NULL CHECK (field IN ('password','private_key','passphrase')),
    ciphertext    BLOB NOT NULL,             -- AES-256-GCM under the credential's DEK
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (credential_id, field)
);

CREATE TABLE crypto_keys (
    version    INTEGER PRIMARY KEY,
    algo       TEXT NOT NULL DEFAULT 'aes-256-gcm',
    kdf        TEXT,                          -- 'argon2id' when derived from a passphrase
    kdf_salt   BLOB,
    kdf_params TEXT,                          -- JSON: {"m":65536,"t":3,"p":4}
    created_at TEXT NOT NULL,
    retired_at TEXT
);
```

Secrets are split into their own table for three reasons: a `SELECT` on `credentials` for
list views cannot accidentally load ciphertext, the `provider` column lets a Vault-backed
credential carry no local ciphertext at all, and per-field rows make rotation auditable.

## 4.5 Snippets

```sql
CREATE TABLE snippet_folders (
    id         TEXT PRIMARY KEY,
    parent_id  TEXT REFERENCES snippet_folders(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    UNIQUE (parent_id, name)
);

CREATE TABLE snippets (
    id             TEXT PRIMARY KEY,
    folder_id      TEXT REFERENCES snippet_folders(id) ON DELETE SET NULL,
    name           TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    body           TEXT NOT NULL,
    shell          TEXT NOT NULL DEFAULT 'sh'
                     CHECK (shell IN ('sh','bash','zsh','fish','powershell','cmd','any')),
    os_family      TEXT,                     -- narrows where it is offered
    variables_json TEXT NOT NULL DEFAULT '[]',
    is_favorite    INTEGER NOT NULL DEFAULT 0 CHECK (is_favorite IN (0,1)),
    hotkey         TEXT,
    run_mode       TEXT NOT NULL DEFAULT 'insert'
                     CHECK (run_mode IN ('insert','run')),
    use_count      INTEGER NOT NULL DEFAULT 0,
    created_by     TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
```

`run_mode` defaults to `insert` — a snippet lands on the command line for the user to
inspect and press Enter, rather than executing on click. Auto-run is opt-in per snippet.
`variables_json` declares each placeholder with a name, label, default, and whether it is
filled automatically from context (`{host}`, `{username}`) or prompted.

## 4.6 Session history, transfers, tunnels, workspaces

```sql
CREATE TABLE session_records (
    id             TEXT PRIMARY KEY,
    user_id        TEXT REFERENCES users(id)  ON DELETE SET NULL,
    host_id        TEXT REFERENCES hosts(id)  ON DELETE SET NULL,
    host_snapshot  TEXT NOT NULL,             -- 'name (user@hostname:port)' preserved if host deleted
    protocol       TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('connecting','connected','disconnected','failed','closed')),
    client_ip      TEXT NOT NULL DEFAULT '',
    started_at     TEXT NOT NULL,
    ended_at       TEXT,
    bytes_in       INTEGER NOT NULL DEFAULT 0,
    bytes_out      INTEGER NOT NULL DEFAULT 0,
    recording_path TEXT,
    exit_reason    TEXT
);
CREATE INDEX idx_session_records_user_started ON session_records(user_id, started_at DESC);
CREATE INDEX idx_session_records_host         ON session_records(host_id, started_at DESC);

CREATE TABLE transfers (
    id                 TEXT PRIMARY KEY,
    user_id            TEXT REFERENCES users(id) ON DELETE SET NULL,
    host_id            TEXT REFERENCES hosts(id) ON DELETE CASCADE,
    direction          TEXT NOT NULL CHECK (direction IN ('upload','download')),
    remote_path        TEXT NOT NULL,
    display_name       TEXT NOT NULL,
    size_bytes         INTEGER,
    transferred_bytes  INTEGER NOT NULL DEFAULT 0,
    status             TEXT NOT NULL CHECK (status IN
                         ('queued','active','completed','failed','cancelled','interrupted')),
    error              TEXT,
    speed_bps          INTEGER,
    retry_count        INTEGER NOT NULL DEFAULT 0,
    queued_at          TEXT NOT NULL,
    started_at         TEXT,
    finished_at        TEXT
);
CREATE INDEX idx_transfers_status ON transfers(status, queued_at);
CREATE INDEX idx_transfers_user   ON transfers(user_id, queued_at DESC);

CREATE TABLE tunnels (                                     -- Phase 2
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('local','remote','socks')),
    listen_host TEXT NOT NULL DEFAULT '127.0.0.1',
    listen_port INTEGER NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    target_host TEXT,
    target_port INTEGER,
    autostart   INTEGER NOT NULL DEFAULT 0 CHECK (autostart IN (0,1)),
    created_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE workspaces (                                  -- Phase 3
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    layout_json TEXT NOT NULL,      -- serialised tab + split tree, host ids only
    is_default  INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0,1)),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE (user_id, name)
);
```

`transfers` rows are the durable queue *and* the history the UI shows — one table, no
sync problem. A backend restart sweeps `active` rows to `interrupted` so the UI can offer
Retry honestly instead of showing a progress bar that will never move.

`session_records.host_snapshot` exists because audit and history must stay legible after a
host is deleted.

## 4.7 Multi-host execution (Phase 2)

```sql
CREATE TABLE exec_jobs (
    id            TEXT PRIMARY KEY,
    user_id       TEXT REFERENCES users(id) ON DELETE SET NULL,
    command       TEXT NOT NULL,
    mode          TEXT NOT NULL CHECK (mode IN ('parallel','sequential')),
    concurrency   INTEGER NOT NULL DEFAULT 8,
    timeout_s     INTEGER NOT NULL DEFAULT 60,
    stop_on_error INTEGER NOT NULL DEFAULT 0 CHECK (stop_on_error IN (0,1)),
    status        TEXT NOT NULL CHECK (status IN ('running','completed','cancelled','failed')),
    risk_ack      TEXT,                    -- what the user typed to confirm a flagged command
    created_at    TEXT NOT NULL,
    finished_at   TEXT
);

CREATE TABLE exec_job_hosts (
    job_id      TEXT NOT NULL REFERENCES exec_jobs(id) ON DELETE CASCADE,
    host_id     TEXT NOT NULL REFERENCES hosts(id)     ON DELETE CASCADE,
    status      TEXT NOT NULL CHECK (status IN
                  ('pending','running','completed','failed','timeout','cancelled','skipped')),
    exit_code   INTEGER,
    stdout      TEXT NOT NULL DEFAULT '',
    stderr      TEXT NOT NULL DEFAULT '',
    truncated   INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0,1)),
    error       TEXT,
    started_at  TEXT,
    finished_at TEXT,
    PRIMARY KEY (job_id, host_id)
);
```

## 4.8 Host discovery (Phase 3)

```sql
CREATE TABLE discovery_scans (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
    cidr        TEXT NOT NULL,
    ports       TEXT NOT NULL,            -- JSON array of probed ports
    status      TEXT NOT NULL CHECK (status IN ('running','completed','cancelled','failed')),
    found_count INTEGER NOT NULL DEFAULT 0,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE discovered_hosts (
    id                TEXT PRIMARY KEY,
    scan_id           TEXT NOT NULL REFERENCES discovery_scans(id) ON DELETE CASCADE,
    ip                TEXT NOT NULL,
    hostname          TEXT,
    mac               TEXT,
    open_ports_json   TEXT NOT NULL DEFAULT '[]',
    ssh_banner        TEXT,               -- banner only; no authentication is attempted
    os_hint           TEXT,
    imported_host_id  TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    seen_at           TEXT NOT NULL
);
```

## 4.9 Audit and settings

```sql
CREATE TABLE audit_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,   -- monotonic ordering
    ts               TEXT NOT NULL,
    user_id          TEXT REFERENCES users(id) ON DELETE SET NULL,
    username         TEXT NOT NULL DEFAULT '',            -- snapshot
    host_id          TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    host_snapshot    TEXT NOT NULL DEFAULT '',
    action           TEXT NOT NULL,        -- 'auth.login', 'session.open', 'file.write', …
    target           TEXT NOT NULL DEFAULT '',
    result           TEXT NOT NULL CHECK (result IN ('success','failure','denied')),
    severity         TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','notice','warning','critical')),
    client_ip        TEXT NOT NULL DEFAULT '',
    auth_session_id  TEXT,
    detail_json      TEXT NOT NULL DEFAULT '{}',
    request_id       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_audit_ts     ON audit_events(ts DESC);
CREATE INDEX idx_audit_user   ON audit_events(user_id, ts DESC);
CREATE INDEX idx_audit_host   ON audit_events(host_id, ts DESC);
CREATE INDEX idx_audit_action ON audit_events(action, ts DESC);

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE user_settings (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, key)
);

CREATE TABLE schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    checksum   TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
```

There is deliberately no `DELETE` path for `audit_events` in the application. Retention is
an administrative operation (`axt-admin audit prune --before`), it is itself audited, and
it is not reachable from the web UI.

## 4.10 Migrations

Numbered, forward-only `.sql` files embedded in the binary and applied in a transaction at
startup, each recorded with a checksum. A checksum mismatch on an already-applied migration
aborts startup rather than silently running a different schema than the one recorded —
which is exactly the failure that turns a routine upgrade into data loss.

```
backend/migrations/
  0001_identity.sql          0005_sessions_transfers.sql
  0002_inventory.sql         0006_audit_settings.sql
  0003_credentials.sql       0007_seed_roles_permissions.sql
  0004_snippets.sql          0008_seed_default_snippets.sql
```

Rollback is by restore-from-backup, not down-migrations: for a single-file database, a
verified copy is more trustworthy than a reverse script that is rarely tested. The upgrade
documentation makes taking that copy step one.
