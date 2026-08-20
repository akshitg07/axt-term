-- 0003: host inventory.

CREATE TABLE folders (
    id         TEXT PRIMARY KEY,
    parent_id  TEXT REFERENCES folders(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    icon       TEXT NOT NULL DEFAULT '',
    color      TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- A unique index rather than a table constraint: SQLite treats NULLs as
-- distinct in UNIQUE constraints, so top-level folders (parent_id IS NULL) would
-- otherwise permit duplicate names.
CREATE UNIQUE INDEX idx_folders_parent_name
    ON folders(COALESCE(parent_id, ''), name COLLATE NOCASE);

CREATE TABLE hosts (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    hostname                TEXT NOT NULL,
    port                    INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol                TEXT NOT NULL
                              CHECK (protocol IN ('ssh', 'sftp', 'rdp', 'vnc', 'telnet', 'serial', 'winrm')),
    folder_id               TEXT REFERENCES folders(id) ON DELETE SET NULL,
    username                TEXT NOT NULL DEFAULT '',
    auth_method             TEXT NOT NULL DEFAULT 'credential'
                              CHECK (auth_method IN ('credential', 'agent', 'password_prompt', 'key_prompt')),
    credential_id           TEXT REFERENCES credentials(id) ON DELETE SET NULL,
    jump_host_id            TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    os_family               TEXT NOT NULL DEFAULT 'unknown'
                              CHECK (os_family IN ('linux', 'windows', 'bsd', 'macos', 'network', 'unknown')),
    color                   TEXT NOT NULL DEFAULT '',
    icon                    TEXT NOT NULL DEFAULT '',
    notes                   TEXT NOT NULL DEFAULT '',
    is_favorite             INTEGER NOT NULL DEFAULT 0 CHECK (is_favorite IN (0, 1)),
    sort_order              INTEGER NOT NULL DEFAULT 0,
    health_check_enabled    INTEGER NOT NULL DEFAULT 0 CHECK (health_check_enabled IN (0, 1)),
    health_check_interval_s INTEGER NOT NULL DEFAULT 300 CHECK (health_check_interval_s >= 30),
    command_logging         TEXT NOT NULL DEFAULT 'inherit'
                              CHECK (command_logging IN ('inherit', 'off', 'commands', 'full')),
    rdp_options_json        TEXT NOT NULL DEFAULT '{}',
    created_by              TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL
);

CREATE INDEX idx_hosts_folder   ON hosts(folder_id);
CREATE INDEX idx_hosts_name     ON hosts(name COLLATE NOCASE);
CREATE INDEX idx_hosts_favorite ON hosts(is_favorite) WHERE is_favorite = 1;
CREATE INDEX idx_hosts_jump     ON hosts(jump_host_id);
CREATE INDEX idx_hosts_cred     ON hosts(credential_id);

CREATE TABLE tags (
    id    TEXT PRIMARY KEY,
    name  TEXT NOT NULL UNIQUE COLLATE NOCASE,
    color TEXT NOT NULL DEFAULT ''
);

CREATE TABLE host_tags (
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    tag_id  TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (host_id, tag_id)
);

CREATE INDEX idx_host_tags_tag ON host_tags(tag_id);

CREATE TABLE host_health (
    host_id    TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    status     TEXT NOT NULL CHECK (status IN ('online', 'slow', 'offline', 'unknown')),
    latency_ms INTEGER,
    checked_at TEXT NOT NULL,
    error      TEXT NOT NULL DEFAULT ''
);

-- Keyed by hostname:port rather than host id, so the same machine reached
-- through two host entries shares one trust decision. A key that changes after
-- being trusted is a hard failure with no override in the connect path.
CREATE TABLE host_keys (
    id                 TEXT PRIMARY KEY,
    hostname           TEXT NOT NULL,
    port               INTEGER NOT NULL,
    key_type           TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    public_key         BLOB NOT NULL,
    first_seen_at      TEXT NOT NULL,
    last_seen_at       TEXT NOT NULL,
    trusted_by         TEXT REFERENCES users(id) ON DELETE SET NULL,
    revoked_at         TEXT,
    UNIQUE (hostname, port, key_type)
);
