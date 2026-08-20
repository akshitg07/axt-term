-- 0006: multi-host command execution.

CREATE TABLE exec_jobs (
    id            TEXT PRIMARY KEY,
    user_id       TEXT REFERENCES users(id) ON DELETE SET NULL,
    command       TEXT NOT NULL,
    mode          TEXT NOT NULL CHECK (mode IN ('parallel', 'sequential')),
    concurrency   INTEGER NOT NULL DEFAULT 8,
    timeout_s     INTEGER NOT NULL DEFAULT 60,
    stop_on_error INTEGER NOT NULL DEFAULT 0 CHECK (stop_on_error IN (0, 1)),
    status        TEXT NOT NULL CHECK (status IN ('running', 'completed', 'cancelled', 'failed')),
    risk_ack      TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    finished_at   TEXT
);

CREATE INDEX idx_exec_jobs_user ON exec_jobs(user_id, created_at DESC);

CREATE TABLE exec_job_hosts (
    job_id      TEXT NOT NULL REFERENCES exec_jobs(id) ON DELETE CASCADE,
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    host_label  TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL CHECK (status IN
                  ('pending', 'running', 'completed', 'failed', 'timeout', 'cancelled', 'skipped')),
    exit_code   INTEGER,
    stdout      TEXT NOT NULL DEFAULT '',
    stderr      TEXT NOT NULL DEFAULT '',
    truncated   INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1)),
    error       TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    started_at  TEXT,
    finished_at TEXT,
    PRIMARY KEY (job_id, host_id)
);
