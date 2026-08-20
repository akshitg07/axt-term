package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

const snippetColumns = `id, folder_id, name, description, body, shell, os_family,
	variables_json, is_favorite, hotkey, run_mode, use_count, created_by, created_at, updated_at`

func scanSnippet(row rowScanner) (*Snippet, error) {
	var (
		s          Snippet
		folderID   sql.NullString
		createdBy  sql.NullString
		varsJSON   string
		isFavorite int
		createdAt  string
		updatedAt  string
	)
	err := row.Scan(&s.ID, &folderID, &s.Name, &s.Description, &s.Body, &s.Shell,
		&s.OSFamily, &varsJSON, &isFavorite, &s.Hotkey, &s.RunMode, &s.UseCount,
		&createdBy, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	s.FolderID = str(folderID)
	s.CreatedBy = str(createdBy)
	s.IsFavorite = isFavorite == 1
	s.CreatedAt = parseTime(createdAt)
	s.UpdatedAt = parseTime(updatedAt)
	s.Variables = []SnippetVariable{}
	if varsJSON != "" {
		// A malformed variables blob must not hide the snippet: the body is still
		// useful and the user can repair the declaration.
		_ = json.Unmarshal([]byte(varsJSON), &s.Variables)
		if s.Variables == nil {
			s.Variables = []SnippetVariable{}
		}
	}
	return &s, nil
}

// SnippetFilter narrows a snippet listing.
type SnippetFilter struct {
	Query    string
	FolderID string
	OSFamily string
	Favorite bool
}

// ListSnippets returns snippets matching the filter.
func (s *Store) ListSnippets(ctx context.Context, f SnippetFilter) ([]*Snippet, error) {
	var (
		where []string
		args  []any
	)
	if f.Query != "" {
		like := "%" + strings.ToLower(f.Query) + "%"
		where = append(where,
			`(LOWER(name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(body) LIKE ?)`)
		args = append(args, like, like, like)
	}
	if f.FolderID != "" {
		where = append(where, `folder_id = ?`)
		args = append(args, f.FolderID)
	}
	if f.OSFamily != "" {
		// An empty os_family means "applies anywhere", so it must still match.
		where = append(where, `(os_family = '' OR os_family = ?)`)
		args = append(args, f.OSFamily)
	}
	if f.Favorite {
		where = append(where, `is_favorite = 1`)
	}

	query := `SELECT ` + snippetColumns + ` FROM snippets`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += ` ORDER BY is_favorite DESC, use_count DESC, name COLLATE NOCASE`

	rows, err := s.read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*Snippet{}
	for rows.Next() {
		sn, err := scanSnippet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

// SnippetByID loads one snippet.
func (s *Store) SnippetByID(ctx context.Context, id string) (*Snippet, error) {
	sn, err := scanSnippet(s.read.QueryRowContext(ctx,
		`SELECT `+snippetColumns+` FROM snippets WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sn, err
}

// CreateSnippet inserts a snippet.
func (s *Store) CreateSnippet(ctx context.Context, sn *Snippet) error {
	now := s.now()
	sn.CreatedAt, sn.UpdatedAt = now, now
	vars, err := json.Marshal(sn.Variables)
	if err != nil {
		return err
	}
	_, err = s.write.ExecContext(ctx,
		`INSERT INTO snippets (`+snippetColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sn.ID, nullIfEmpty(sn.FolderID), sn.Name, sn.Description, sn.Body, sn.Shell,
		sn.OSFamily, string(vars), boolInt(sn.IsFavorite), sn.Hotkey, string(sn.RunMode),
		sn.UseCount, nullIfEmpty(sn.CreatedBy), fmtTime(sn.CreatedAt), fmtTime(sn.UpdatedAt))
	return mapWriteError(err)
}

// UpdateSnippet replaces a snippet's fields.
func (s *Store) UpdateSnippet(ctx context.Context, sn *Snippet) error {
	sn.UpdatedAt = s.now()
	vars, err := json.Marshal(sn.Variables)
	if err != nil {
		return err
	}
	res, err := s.write.ExecContext(ctx, `
		UPDATE snippets SET folder_id = ?, name = ?, description = ?, body = ?, shell = ?,
			os_family = ?, variables_json = ?, is_favorite = ?, hotkey = ?, run_mode = ?,
			updated_at = ?
		WHERE id = ?`,
		nullIfEmpty(sn.FolderID), sn.Name, sn.Description, sn.Body, sn.Shell,
		sn.OSFamily, string(vars), boolInt(sn.IsFavorite), sn.Hotkey, string(sn.RunMode),
		fmtTime(sn.UpdatedAt), sn.ID)
	return affected(res, err)
}

// DeleteSnippet removes a snippet.
func (s *Store) DeleteSnippet(ctx context.Context, id string) error {
	res, err := s.write.ExecContext(ctx, `DELETE FROM snippets WHERE id = ?`, id)
	return affected(res, err)
}

// IncrementSnippetUse bumps the counter that drives ordering, so the snippets an
// engineer actually reaches for rise to the top.
func (s *Store) IncrementSnippetUse(ctx context.Context, id string) error {
	_, err := s.write.ExecContext(ctx,
		`UPDATE snippets SET use_count = use_count + 1 WHERE id = ?`, id)
	return err
}

// ListSnippetFolders returns the snippet folder tree.
func (s *Store) ListSnippetFolders(ctx context.Context) ([]*SnippetFolder, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT id, parent_id, name, sort_order FROM snippet_folders
		 ORDER BY sort_order, name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*SnippetFolder{}
	for rows.Next() {
		var (
			f        SnippetFolder
			parentID sql.NullString
		)
		if err := rows.Scan(&f.ID, &parentID, &f.Name, &f.SortOrder); err != nil {
			return nil, err
		}
		f.ParentID = str(parentID)
		out = append(out, &f)
	}
	return out, rows.Err()
}

// CreateSnippetFolder inserts a snippet folder.
func (s *Store) CreateSnippetFolder(ctx context.Context, f *SnippetFolder) error {
	_, err := s.write.ExecContext(ctx,
		`INSERT INTO snippet_folders (id, parent_id, name, sort_order) VALUES (?, ?, ?, ?)`,
		f.ID, nullIfEmpty(f.ParentID), f.Name, f.SortOrder)
	return mapWriteError(err)
}

// UpdateSnippetFolder renames or reorders a snippet folder.
func (s *Store) UpdateSnippetFolder(ctx context.Context, f *SnippetFolder) error {
	res, err := s.write.ExecContext(ctx,
		`UPDATE snippet_folders SET parent_id = ?, name = ?, sort_order = ? WHERE id = ?`,
		nullIfEmpty(f.ParentID), f.Name, f.SortOrder, f.ID)
	return affected(res, err)
}

// DeleteSnippetFolder removes a folder; its snippets move to the root.
func (s *Store) DeleteSnippetFolder(ctx context.Context, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`UPDATE snippets SET folder_id = NULL WHERE folder_id = ?`, id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM snippet_folders WHERE id = ?`, id)
		return affected(res, err)
	})
}
