-- 0005: session history, transfers, tunnels, workspaces.
--
-- host_snapshot columns exist because history and audit must stay legible after
-- a host is deleted.

CREATE TABLE session_records (
    id             TEXT PRIMARY KEY,
    user_id        TEXT REFERENCES users(id) ON DELETE SET NULL,
    host_id        TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    host_snapshot  TEXT NOT NULL DEFAULT '',
    protocol       TEXT NOT NULL,
    status         TEXT NOT NULL
                     CHECK (status IN ('connecting', 'connected', 'disconnected', 'failed', 'closed')),
    client_ip      TEXT NOT NULL DEFAULT '',
    started_at     TEXT NOT NULL,
    ended_at       TEXT,
    bytes_in       INTEGER NOT NULL DEFAULT 0,
    bytes_out      INTEGER NOT NULL DEFAULT 0,
    recording_path TEXT NOT NULL DEFAULT '',
    exit_reason    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_session_records_user ON session_records(user_id, started_at DESC);
CREATE INDEX idx_session_records_host ON session_records(host_id, started_at DESC);

-- This table is both the durable queue and the history the UI shows. One table,
-- so there is no synchronisation problem between them.
CREATE TABLE transfers (
    id                TEXT PRIMARY KEY,
    user_id           TEXT REFERENCES users(id) ON DELETE SET NULL,
    host_id           TEXT REFERENCES hosts(id) ON DELETE CASCADE,
    direction         TEXT NOT NULL CHECK (direction IN ('upload', 'download')),
    remote_path       TEXT NOT NULL,
    display_name      TEXT NOT NULL,
    size_bytes        INTEGER,
    transferred_bytes INTEGER NOT NULL DEFAULT 0,
    status            TEXT NOT NULL CHECK (status IN
                        ('queued', 'active', 'completed', 'failed', 'cancelled', 'interrupted')),
    error             TEXT NOT NULL DEFAULT '',
    speed_bps         INTEGER NOT NULL DEFAULT 0,
    retry_count       INTEGER NOT NULL DEFAULT 0,
    queued_at         TEXT NOT NULL,
    started_at        TEXT,
    finished_at       TEXT
);

CREATE INDEX idx_transfers_status ON transfers(status, queued_at);
CREATE INDEX idx_transfers_user   ON transfers(user_id, queued_at DESC);

CREATE TABLE tunnels (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('local', 'remote', 'socks')),
    listen_host TEXT NOT NULL DEFAULT '127.0.0.1',
    listen_port INTEGER NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    target_host TEXT NOT NULL DEFAULT '',
    target_port INTEGER NOT NULL DEFAULT 0,
    autostart   INTEGER NOT NULL DEFAULT 0 CHECK (autostart IN (0, 1)),
    created_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE INDEX idx_tunnels_host ON tunnels(host_id);

CREATE TABLE workspaces (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    layout_json TEXT NOT NULL DEFAULT '{}',
    is_default  INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE (user_id, name)
);
