-- 0004: command snippets.
--
-- run_mode defaults to 'insert': a snippet lands on the command line for review
-- rather than executing on click. Auto-run is opt-in per snippet.

CREATE TABLE snippet_folders (
    id         TEXT PRIMARY KEY,
    parent_id  TEXT REFERENCES snippet_folders(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX idx_snippet_folders_parent_name
    ON snippet_folders(COALESCE(parent_id, ''), name COLLATE NOCASE);

CREATE TABLE snippets (
    id             TEXT PRIMARY KEY,
    folder_id      TEXT REFERENCES snippet_folders(id) ON DELETE SET NULL,
    name           TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    body           TEXT NOT NULL,
    shell          TEXT NOT NULL DEFAULT 'sh'
                     CHECK (shell IN ('sh', 'bash', 'zsh', 'fish', 'powershell', 'cmd', 'any')),
    os_family      TEXT NOT NULL DEFAULT '',
    variables_json TEXT NOT NULL DEFAULT '[]',
    is_favorite    INTEGER NOT NULL DEFAULT 0 CHECK (is_favorite IN (0, 1)),
    hotkey         TEXT NOT NULL DEFAULT '',
    run_mode       TEXT NOT NULL DEFAULT 'insert' CHECK (run_mode IN ('insert', 'run')),
    use_count      INTEGER NOT NULL DEFAULT 0,
    created_by     TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE INDEX idx_snippets_folder ON snippets(folder_id);
CREATE INDEX idx_snippets_name   ON snippets(name COLLATE NOCASE);
