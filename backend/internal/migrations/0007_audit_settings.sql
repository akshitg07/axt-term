-- 0007: audit log, discovery, and settings.
--
-- audit_events uses an AUTOINCREMENT integer key for monotonic ordering, and the
-- application provides no DELETE path. Retention is an explicit admin action
-- (`axt-admin audit prune`), is itself audited, and is unreachable from the web UI.

CREATE TABLE audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    user_id         TEXT REFERENCES users(id) ON DELETE SET NULL,
    username        TEXT NOT NULL DEFAULT '',
    host_id         TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    host_snapshot   TEXT NOT NULL DEFAULT '',
    action          TEXT NOT NULL,
    target          TEXT NOT NULL DEFAULT '',
    result          TEXT NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    severity        TEXT NOT NULL DEFAULT 'info'
                      CHECK (severity IN ('info', 'notice', 'warning', 'critical')),
    client_ip       TEXT NOT NULL DEFAULT '',
    auth_session_id TEXT NOT NULL DEFAULT '',
    detail_json     TEXT NOT NULL DEFAULT '{}',
    request_id      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_audit_ts     ON audit_events(ts DESC);
CREATE INDEX idx_audit_user   ON audit_events(user_id, ts DESC);
CREATE INDEX idx_audit_host   ON audit_events(host_id, ts DESC);
CREATE INDEX idx_audit_action ON audit_events(action, ts DESC);

CREATE TABLE discovery_scans (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
    cidr        TEXT NOT NULL,
    ports       TEXT NOT NULL DEFAULT '[]',
    status      TEXT NOT NULL CHECK (status IN ('running', 'completed', 'cancelled', 'failed')),
    found_count INTEGER NOT NULL DEFAULT 0,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE discovered_hosts (
    id               TEXT PRIMARY KEY,
    scan_id          TEXT NOT NULL REFERENCES discovery_scans(id) ON DELETE CASCADE,
    ip               TEXT NOT NULL,
    hostname         TEXT NOT NULL DEFAULT '',
    mac              TEXT NOT NULL DEFAULT '',
    open_ports_json  TEXT NOT NULL DEFAULT '[]',
    ssh_banner       TEXT NOT NULL DEFAULT '',
    os_hint          TEXT NOT NULL DEFAULT '',
    imported_host_id TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    seen_at          TEXT NOT NULL
);

CREATE INDEX idx_discovered_scan ON discovered_hosts(scan_id);

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
