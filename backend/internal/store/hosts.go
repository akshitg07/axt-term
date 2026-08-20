package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ----------------------------------------------------------------- folders ---

const folderColumns = `id, parent_id, name, icon, color, sort_order, created_at, updated_at`

func scanFolder(row rowScanner) (*Folder, error) {
	var (
		f         Folder
		parentID  sql.NullString
		createdAt string
		updatedAt string
	)
	if err := row.Scan(&f.ID, &parentID, &f.Name, &f.Icon, &f.Color, &f.SortOrder,
		&createdAt, &updatedAt); err != nil {
		return nil, err
	}
	f.ParentID = str(parentID)
	f.CreatedAt = parseTime(createdAt)
	f.UpdatedAt = parseTime(updatedAt)
	return &f, nil
}

// ListFolders returns every folder ordered for tree rendering.
func (s *Store) ListFolders(ctx context.Context) ([]*Folder, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT `+folderColumns+` FROM folders ORDER BY sort_order, name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*Folder{}
	for rows.Next() {
		f, err := scanFolder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// FolderByID loads one folder.
func (s *Store) FolderByID(ctx context.Context, id string) (*Folder, error) {
	f, err := scanFolder(s.read.QueryRowContext(ctx,
		`SELECT `+folderColumns+` FROM folders WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return f, err
}

// FolderPaths returns id to slash-separated path, for display and search.
func (s *Store) FolderPaths(ctx context.Context) (map[string]string, error) {
	rows, err := s.read.QueryContext(ctx, `
		WITH RECURSIVE tree(id, path) AS (
			SELECT id, name FROM folders WHERE parent_id IS NULL
			UNION ALL
			SELECT f.id, tree.path || '/' || f.name
			FROM folders f JOIN tree ON f.parent_id = tree.id
		)
		SELECT id, path FROM tree`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]string)
	for rows.Next() {
		var id, path string
		if err := rows.Scan(&id, &path); err != nil {
			return nil, err
		}
		out[id] = path
	}
	return out, rows.Err()
}

// CreateFolder inserts a folder.
func (s *Store) CreateFolder(ctx context.Context, f *Folder) error {
	now := s.now()
	f.CreatedAt, f.UpdatedAt = now, now
	_, err := s.write.ExecContext(ctx,
		`INSERT INTO folders (`+folderColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, nullIfEmpty(f.ParentID), f.Name, f.Icon, f.Color, f.SortOrder,
		fmtTime(f.CreatedAt), fmtTime(f.UpdatedAt))
	return mapWriteError(err)
}

// UpdateFolder changes a folder's presentation fields.
func (s *Store) UpdateFolder(ctx context.Context, f *Folder) error {
	f.UpdatedAt = s.now()
	res, err := s.write.ExecContext(ctx, `
		UPDATE folders SET name = ?, icon = ?, color = ?, sort_order = ?, updated_at = ?
		WHERE id = ?`,
		f.Name, f.Icon, f.Color, f.SortOrder, fmtTime(f.UpdatedAt), f.ID)
	return affected(res, err)
}

// MoveFolder reparents a folder, refusing to create a cycle.
//
// Without this check a folder could be moved inside its own descendant, which
// detaches the whole branch from the tree: the rows still exist but nothing
// renders them, and it looks like data loss.
func (s *Store) MoveFolder(ctx context.Context, id, newParentID string, sortOrder int) error {
	if id == newParentID && id != "" {
		return fmt.Errorf("%w: a folder cannot be its own parent", ErrConflict)
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if newParentID != "" {
			descendant, err := folderIsDescendant(ctx, tx, newParentID, id)
			if err != nil {
				return err
			}
			if descendant {
				return fmt.Errorf("%w: moving this folder into %s would create a cycle", ErrConflict, newParentID)
			}
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE folders SET parent_id = ?, sort_order = ?, updated_at = ? WHERE id = ?`,
			nullIfEmpty(newParentID), sortOrder, fmtTime(s.now()), id)
		return affected(res, err)
	})
}

// folderIsDescendant reports whether candidate sits below ancestor.
func folderIsDescendant(ctx context.Context, tx *sql.Tx, candidate, ancestor string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `
		WITH RECURSIVE up(id, parent_id) AS (
			SELECT id, parent_id FROM folders WHERE id = ?
			UNION ALL
			SELECT f.id, f.parent_id FROM folders f JOIN up ON f.id = up.parent_id
		)
		SELECT COUNT(*) FROM up WHERE id = ?`, candidate, ancestor)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	var n int
	if rows.Next() {
		if err := rows.Scan(&n); err != nil {
			return false, err
		}
	}
	return n > 0, rows.Err()
}

// DeleteFolderStrategy selects what happens to a deleted folder's contents.
type DeleteFolderStrategy string

const (
	// StrategyOrphan keeps hosts and moves them to the root. The default,
	// because deleting a folder is a filing decision and should not destroy
	// inventory.
	StrategyOrphan DeleteFolderStrategy = "orphan"
	// StrategyCascade deletes the subtree and the hosts within it.
	StrategyCascade DeleteFolderStrategy = "cascade"
)

// DeleteFolder removes a folder using the given strategy.
func (s *Store) DeleteFolder(ctx context.Context, id string, strategy DeleteFolderStrategy) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if strategy == StrategyOrphan {
			// Detach hosts and child folders first so the cascade cannot reach
			// them, then delete just this row.
			if _, err := tx.ExecContext(ctx,
				`UPDATE hosts SET folder_id = NULL, updated_at = ? WHERE folder_id = ?`,
				fmtTime(s.now()), id); err != nil {
				return err
			}
			var parentID sql.NullString
			if err := tx.QueryRowContext(ctx,
				`SELECT parent_id FROM folders WHERE id = ?`, id).Scan(&parentID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrNotFound
				}
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`UPDATE folders SET parent_id = ?, updated_at = ? WHERE parent_id = ?`,
				nullIfEmpty(str(parentID)), fmtTime(s.now()), id); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM folders WHERE id = ?`, id)
		return affected(res, err)
	})
}

// ------------------------------------------------------------------- hosts ---

const hostColumns = `id, name, hostname, port, protocol, folder_id, username, auth_method,
	credential_id, jump_host_id, os_family, color, icon, notes, is_favorite, sort_order,
	health_check_enabled, health_check_interval_s, command_logging, rdp_options_json,
	created_by, created_at, updated_at`

func scanHost(row rowScanner) (*Host, error) {
	var (
		h            Host
		folderID     sql.NullString
		credentialID sql.NullString
		jumpHostID   sql.NullString
		createdBy    sql.NullString
		rdpJSON      string
		isFavorite   int
		healthOn     int
		createdAt    string
		updatedAt    string
	)
	err := row.Scan(&h.ID, &h.Name, &h.Hostname, &h.Port, &h.Protocol, &folderID,
		&h.Username, &h.AuthMethod, &credentialID, &jumpHostID, &h.OSFamily,
		&h.Color, &h.Icon, &h.Notes, &isFavorite, &h.SortOrder,
		&healthOn, &h.HealthCheckIntervalS, &h.CommandLogging, &rdpJSON,
		&createdBy, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	h.FolderID = str(folderID)
	h.CredentialID = str(credentialID)
	h.JumpHostID = str(jumpHostID)
	h.CreatedBy = str(createdBy)
	h.IsFavorite = isFavorite == 1
	h.HealthCheckEnabled = healthOn == 1
	h.CreatedAt = parseTime(createdAt)
	h.UpdatedAt = parseTime(updatedAt)
	h.Tags = []string{}
	if rdpJSON != "" && rdpJSON != "{}" {
		// A malformed options blob must not make the host unreadable; the host
		// is still usable for SSH and the operator can fix the RDP settings.
		_ = json.Unmarshal([]byte(rdpJSON), &h.RDPOptions)
	}
	return &h, nil
}

// HostFilter narrows a host listing.
type HostFilter struct {
	Query         string
	FolderID      string
	Tag           string
	Protocol      Protocol
	OSFamily      OSFamily
	FavoritesOnly bool
	Sort          string // name (default), hostname, recent, created
}

// ListHosts returns hosts matching the filter, with tags and health attached.
func (s *Store) ListHosts(ctx context.Context, f HostFilter) ([]*Host, error) {
	var (
		where []string
		args  []any
	)

	if f.Query != "" {
		// Matching name, hostname, and notes together is what makes one search
		// box enough: engineers remember any one of the three.
		like := "%" + strings.ToLower(f.Query) + "%"
		where = append(where, `(LOWER(h.name) LIKE ? OR LOWER(h.hostname) LIKE ? OR LOWER(h.notes) LIKE ?)`)
		args = append(args, like, like, like)
	}
	if f.FolderID != "" {
		where = append(where, `h.folder_id = ?`)
		args = append(args, f.FolderID)
	}
	if f.Protocol != "" {
		where = append(where, `h.protocol = ?`)
		args = append(args, string(f.Protocol))
	}
	if f.OSFamily != "" {
		where = append(where, `h.os_family = ?`)
		args = append(args, string(f.OSFamily))
	}
	if f.FavoritesOnly {
		where = append(where, `h.is_favorite = 1`)
	}
	if f.Tag != "" {
		where = append(where, `EXISTS (
			SELECT 1 FROM host_tags ht JOIN tags t ON t.id = ht.tag_id
			WHERE ht.host_id = h.id AND t.name = ?)`)
		args = append(args, f.Tag)
	}

	// Columns are table-qualified because the sort options join session_records.
	query := `SELECT ` + qualify(hostColumns, "h") + ` FROM hosts h`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	switch f.Sort {
	case "hostname":
		query += " ORDER BY h.hostname COLLATE NOCASE"
	case "created":
		query += " ORDER BY h.created_at DESC"
	case "recent":
		query += ` ORDER BY COALESCE((SELECT MAX(started_at) FROM session_records sr
			WHERE sr.host_id = h.id), '') DESC, h.name COLLATE NOCASE`
	default:
		query += " ORDER BY h.is_favorite DESC, h.sort_order, h.name COLLATE NOCASE"
	}

	rows, err := s.read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*Host{}
	byID := make(map[string]*Host)
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
		byID[h.ID] = h
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}

	if err := s.attachTags(ctx, byID); err != nil {
		return nil, err
	}
	if err := s.attachHealth(ctx, byID); err != nil {
		return nil, err
	}
	paths, err := s.FolderPaths(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range out {
		if h.FolderID != "" {
			h.FolderPath = paths[h.FolderID]
		}
	}
	return out, nil
}

// qualify prefixes each column in a comma-separated list with a table alias.
func qualify(columns, alias string) string {
	parts := strings.Split(columns, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

func (s *Store) attachTags(ctx context.Context, byID map[string]*Host) error {
	rows, err := s.read.QueryContext(ctx, `
		SELECT ht.host_id, t.name
		FROM host_tags ht JOIN tags t ON t.id = ht.tag_id
		ORDER BY t.name`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var hostID, tag string
		if err := rows.Scan(&hostID, &tag); err != nil {
			return err
		}
		if h, ok := byID[hostID]; ok {
			h.Tags = append(h.Tags, tag)
		}
	}
	return rows.Err()
}

func (s *Store) attachHealth(ctx context.Context, byID map[string]*Host) error {
	rows, err := s.read.QueryContext(ctx,
		`SELECT host_id, status, latency_ms, checked_at, error FROM host_health`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			hh        HostHealth
			latency   sql.NullInt64
			checkedAt string
		)
		if err := rows.Scan(&hh.HostID, &hh.Status, &latency, &checkedAt, &hh.Error); err != nil {
			return err
		}
		hh.LatencyMS = intPtr(latency)
		hh.CheckedAt = parseTime(checkedAt)
		if h, ok := byID[hh.HostID]; ok {
			copied := hh
			h.Health = &copied
		}
	}
	return rows.Err()
}

// HostByID loads one host with its tags and health.
func (s *Store) HostByID(ctx context.Context, id string) (*Host, error) {
	h, err := scanHost(s.read.QueryRowContext(ctx,
		`SELECT `+hostColumns+` FROM hosts WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	byID := map[string]*Host{h.ID: h}
	if err := s.attachTags(ctx, byID); err != nil {
		return nil, err
	}
	if err := s.attachHealth(ctx, byID); err != nil {
		return nil, err
	}
	if h.FolderID != "" {
		if paths, err := s.FolderPaths(ctx); err == nil {
			h.FolderPath = paths[h.FolderID]
		}
	}
	return h, nil
}

// HostsByIDs loads several hosts, preserving no particular order.
func (s *Store) HostsByIDs(ctx context.Context, ids []string) ([]*Host, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := s.read.QueryContext(ctx,
		`SELECT `+hostColumns+` FROM hosts WHERE id IN (`+joinPlaceholders(len(ids))+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// CreateHost inserts a host and sets its tags.
func (s *Store) CreateHost(ctx context.Context, h *Host, tagNames []string) error {
	now := s.now()
	h.CreatedAt, h.UpdatedAt = now, now
	return s.tx(ctx, func(tx *sql.Tx) error {
		if h.JumpHostID != "" {
			if err := checkJumpChainTx(ctx, tx, h.ID, h.JumpHostID, 0); err != nil {
				return err
			}
		}
		rdpJSON, err := json.Marshal(h.RDPOptions)
		if err != nil {
			return fmt.Errorf("store: encode rdp options: %w", err)
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO hosts (`+hostColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			h.ID, h.Name, h.Hostname, h.Port, string(h.Protocol), nullIfEmpty(h.FolderID),
			h.Username, string(h.AuthMethod), nullIfEmpty(h.CredentialID), nullIfEmpty(h.JumpHostID),
			string(h.OSFamily), h.Color, h.Icon, h.Notes, boolInt(h.IsFavorite), h.SortOrder,
			boolInt(h.HealthCheckEnabled), h.HealthCheckIntervalS, string(h.CommandLogging), string(rdpJSON),
			nullIfEmpty(h.CreatedBy), fmtTime(h.CreatedAt), fmtTime(h.UpdatedAt))
		if err != nil {
			return mapWriteError(err)
		}
		return setHostTagsTx(ctx, tx, h.ID, tagNames)
	})
}

// UpdateHost replaces a host's mutable fields and tags.
func (s *Store) UpdateHost(ctx context.Context, h *Host, tagNames []string) error {
	h.UpdatedAt = s.now()
	return s.tx(ctx, func(tx *sql.Tx) error {
		if h.JumpHostID != "" {
			if err := checkJumpChainTx(ctx, tx, h.ID, h.JumpHostID, 0); err != nil {
				return err
			}
		}
		rdpJSON, err := json.Marshal(h.RDPOptions)
		if err != nil {
			return fmt.Errorf("store: encode rdp options: %w", err)
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE hosts SET name = ?, hostname = ?, port = ?, protocol = ?, folder_id = ?,
				username = ?, auth_method = ?, credential_id = ?, jump_host_id = ?, os_family = ?,
				color = ?, icon = ?, notes = ?, is_favorite = ?, sort_order = ?,
				health_check_enabled = ?, health_check_interval_s = ?, command_logging = ?,
				rdp_options_json = ?, updated_at = ?
			WHERE id = ?`,
			h.Name, h.Hostname, h.Port, string(h.Protocol), nullIfEmpty(h.FolderID),
			h.Username, string(h.AuthMethod), nullIfEmpty(h.CredentialID), nullIfEmpty(h.JumpHostID),
			string(h.OSFamily), h.Color, h.Icon, h.Notes, boolInt(h.IsFavorite), h.SortOrder,
			boolInt(h.HealthCheckEnabled), h.HealthCheckIntervalS, string(h.CommandLogging),
			string(rdpJSON), fmtTime(h.UpdatedAt), h.ID)
		if err := affected(res, err); err != nil {
			return err
		}
		return setHostTagsTx(ctx, tx, h.ID, tagNames)
	})
}

// maxJumpChainDepth bounds a chain independently of the configured limit, so a
// malformed inventory cannot make resolution loop.
const maxJumpChainDepth = 16

// checkJumpChainTx walks a proposed jump chain looking for a cycle back to the
// host being edited. A cycle here would make every connection attempt hang.
func checkJumpChainTx(ctx context.Context, tx *sql.Tx, hostID, jumpID string, depth int) error {
	if depth > maxJumpChainDepth {
		return fmt.Errorf("%w: jump host chain is longer than %d hops", ErrConflict, maxJumpChainDepth)
	}
	if jumpID == "" {
		return nil
	}
	if jumpID == hostID {
		return fmt.Errorf("%w: a host cannot be its own jump host, directly or through a chain", ErrConflict)
	}
	var next sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT jump_host_id FROM hosts WHERE id = ?`, jumpID).Scan(&next)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: jump host %s", ErrNotFound, jumpID)
	}
	if err != nil {
		return err
	}
	return checkJumpChainTx(ctx, tx, hostID, str(next), depth+1)
}

// JumpChain resolves a host's chain from the outermost bastion to the target.
// The returned slice ends with the requested host.
func (s *Store) JumpChain(ctx context.Context, hostID string, maxHops int) ([]*Host, error) {
	if maxHops <= 0 {
		maxHops = maxJumpChainDepth
	}
	var chain []*Host
	seen := make(map[string]bool)
	current := hostID

	for current != "" {
		if seen[current] {
			return nil, fmt.Errorf("%w: jump host chain contains a cycle at %s", ErrConflict, current)
		}
		seen[current] = true

		h, err := s.HostByID(ctx, current)
		if err != nil {
			return nil, err
		}
		// Prepend: we walk target -> bastion but must dial bastion -> target.
		chain = append([]*Host{h}, chain...)
		if len(chain) > maxHops+1 {
			return nil, fmt.Errorf("%w: jump host chain exceeds %d hops", ErrConflict, maxHops)
		}
		current = h.JumpHostID
	}
	return chain, nil
}

// SetHostFavorite toggles the favourite flag.
func (s *Store) SetHostFavorite(ctx context.Context, id string, favorite bool) error {
	res, err := s.write.ExecContext(ctx,
		`UPDATE hosts SET is_favorite = ?, updated_at = ? WHERE id = ?`,
		boolInt(favorite), fmtTime(s.now()), id)
	return affected(res, err)
}

// DeleteHost removes a host.
func (s *Store) DeleteHost(ctx context.Context, id string) error {
	res, err := s.write.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, id)
	return affected(res, err)
}

// HostsReferencingCredential lists hosts that would lose their credential.
func (s *Store) HostsReferencingCredential(ctx context.Context, credentialID string) ([]*Host, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT `+hostColumns+` FROM hosts WHERE credential_id = ? ORDER BY name COLLATE NOCASE`,
		credentialID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// -------------------------------------------------------------------- tags ---

// ListTags returns tags with how many hosts carry each.
func (s *Store) ListTags(ctx context.Context) ([]*Tag, error) {
	rows, err := s.read.QueryContext(ctx, `
		SELECT t.id, t.name, t.color, COUNT(ht.host_id)
		FROM tags t LEFT JOIN host_tags ht ON ht.tag_id = t.id
		GROUP BY t.id, t.name, t.color
		ORDER BY t.name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*Tag{}
	for rows.Next() {
		var t Tag
		if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.Count); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

// CreateTag inserts a tag.
func (s *Store) CreateTag(ctx context.Context, t *Tag) error {
	_, err := s.write.ExecContext(ctx,
		`INSERT INTO tags (id, name, color) VALUES (?, ?, ?)`, t.ID, t.Name, t.Color)
	return mapWriteError(err)
}

// UpdateTag changes a tag's colour or name.
func (s *Store) UpdateTag(ctx context.Context, t *Tag) error {
	res, err := s.write.ExecContext(ctx,
		`UPDATE tags SET name = ?, color = ? WHERE id = ?`, t.Name, t.Color, t.ID)
	return affected(res, err)
}

// DeleteTag removes a tag and its host associations.
func (s *Store) DeleteTag(ctx context.Context, id string) error {
	res, err := s.write.ExecContext(ctx, `DELETE FROM tags WHERE id = ?`, id)
	return affected(res, err)
}

// SetHostTags replaces a host's tags, creating any that do not exist.
func (s *Store) SetHostTags(ctx context.Context, hostID string, tagNames []string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		return setHostTagsTx(ctx, tx, hostID, tagNames)
	})
}

func setHostTagsTx(ctx context.Context, tx *sql.Tx, hostID string, tagNames []string) error {
	if tagNames == nil {
		return nil // nil means "leave tags alone"; an empty slice clears them
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM host_tags WHERE host_id = ?`, hostID); err != nil {
		return err
	}
	for _, raw := range tagNames {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		var tagID string
		err := tx.QueryRowContext(ctx, `SELECT id FROM tags WHERE name = ?`, name).Scan(&tagID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// Tags are created implicitly: making a user visit a separate screen
			// before labelling a host is friction with no purpose.
			tagID = newTagID(name)
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO tags (id, name, color) VALUES (?, ?, '')`, tagID, name); err != nil {
				return mapWriteError(err)
			}
		case err != nil:
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO host_tags (host_id, tag_id) VALUES (?, ?)`, hostID, tagID); err != nil {
			return mapWriteError(err)
		}
	}
	return nil
}

// newTagID derives a stable, readable id from a tag name.
func newTagID(name string) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		case r == ' ' || r == '-' || r == '_':
			return '-'
		default:
			return -1
		}
	}, name)
	if slug == "" {
		slug = "tag"
	}
	return "tag-" + slug
}

// ------------------------------------------------------------------ health ---

// UpsertHostHealth records a health check result.
func (s *Store) UpsertHostHealth(ctx context.Context, h *HostHealth) error {
	_, err := s.write.ExecContext(ctx, `
		INSERT INTO host_health (host_id, status, latency_ms, checked_at, error)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(host_id) DO UPDATE SET
			status = excluded.status,
			latency_ms = excluded.latency_ms,
			checked_at = excluded.checked_at,
			error = excluded.error`,
		h.HostID, string(h.Status), latencyArg(h.LatencyMS), fmtTime(h.CheckedAt), h.Error)
	return err
}

func latencyArg(ms *int) any {
	if ms == nil {
		return nil
	}
	return *ms
}

// HostsDueForHealthCheck returns hosts whose check interval has elapsed.
//
// Only hosts with checking explicitly enabled are returned: polling an entire
// inventory by default is exactly the aggressive behaviour the design rules out.
func (s *Store) HostsDueForHealthCheck(ctx context.Context, now time.Time, limit int) ([]*Host, error) {
	if limit <= 0 {
		limit = 25
	}
	rows, err := s.read.QueryContext(ctx, `
		SELECT `+qualify(hostColumns, "h")+`
		FROM hosts h LEFT JOIN host_health hh ON hh.host_id = h.id
		WHERE h.health_check_enabled = 1
		  AND (hh.checked_at IS NULL
		       OR CAST(strftime('%s', ?) AS INTEGER) - CAST(strftime('%s', hh.checked_at) AS INTEGER)
		          >= h.health_check_interval_s)
		ORDER BY COALESCE(hh.checked_at, '') ASC
		LIMIT ?`, fmtTime(now), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// --------------------------------------------------------------- host keys ---

// TrustedHostKey returns a trusted key for hostname:port of the given type.
func (s *Store) TrustedHostKey(ctx context.Context, hostname string, port int, keyType string) (*HostKey, error) {
	row := s.read.QueryRowContext(ctx, `
		SELECT id, hostname, port, key_type, fingerprint_sha256, public_key,
		       first_seen_at, last_seen_at, trusted_by, revoked_at
		FROM host_keys
		WHERE hostname = ? AND port = ? AND key_type = ? AND revoked_at IS NULL`,
		hostname, port, keyType)
	return scanHostKey(row)
}

// HostKeysFor returns every recorded key for an endpoint, including revoked ones,
// so an administrator can see the history behind a mismatch.
func (s *Store) HostKeysFor(ctx context.Context, hostname string, port int) ([]*HostKey, error) {
	rows, err := s.read.QueryContext(ctx, `
		SELECT id, hostname, port, key_type, fingerprint_sha256, public_key,
		       first_seen_at, last_seen_at, trusted_by, revoked_at
		FROM host_keys WHERE hostname = ? AND port = ? ORDER BY key_type`, hostname, port)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*HostKey{}
	for rows.Next() {
		k, err := scanHostKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// ListHostKeys returns the whole trust store.
func (s *Store) ListHostKeys(ctx context.Context) ([]*HostKey, error) {
	rows, err := s.read.QueryContext(ctx, `
		SELECT id, hostname, port, key_type, fingerprint_sha256, public_key,
		       first_seen_at, last_seen_at, trusted_by, revoked_at
		FROM host_keys ORDER BY hostname, port, key_type`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*HostKey{}
	for rows.Next() {
		k, err := scanHostKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func scanHostKey(row rowScanner) (*HostKey, error) {
	var (
		k         HostKey
		trustedBy sql.NullString
		revokedAt sql.NullString
		firstSeen string
		lastSeen  string
	)
	err := row.Scan(&k.ID, &k.Hostname, &k.Port, &k.KeyType, &k.FingerprintSHA256,
		&k.PublicKey, &firstSeen, &lastSeen, &trustedBy, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	k.TrustedBy = str(trustedBy)
	k.RevokedAt = timePtr(revokedAt)
	k.FirstSeenAt = parseTime(firstSeen)
	k.LastSeenAt = parseTime(lastSeen)
	return &k, nil
}

// TrustHostKey records a key as trusted. Used by the trust-on-first-use flow
// after the user has confirmed the fingerprint.
func (s *Store) TrustHostKey(ctx context.Context, k *HostKey) error {
	now := s.now()
	if k.FirstSeenAt.IsZero() {
		k.FirstSeenAt = now
	}
	k.LastSeenAt = now
	_, err := s.write.ExecContext(ctx, `
		INSERT INTO host_keys (id, hostname, port, key_type, fingerprint_sha256, public_key,
			first_seen_at, last_seen_at, trusted_by, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		ON CONFLICT(hostname, port, key_type) DO UPDATE SET
			fingerprint_sha256 = excluded.fingerprint_sha256,
			public_key = excluded.public_key,
			last_seen_at = excluded.last_seen_at,
			trusted_by = excluded.trusted_by,
			revoked_at = NULL`,
		k.ID, k.Hostname, k.Port, k.KeyType, k.FingerprintSHA256, k.PublicKey,
		fmtTime(k.FirstSeenAt), fmtTime(k.LastSeenAt), nullIfEmpty(k.TrustedBy))
	return mapWriteError(err)
}

// TouchHostKey updates the last-seen time after a successful match.
func (s *Store) TouchHostKey(ctx context.Context, id string) error {
	_, err := s.write.ExecContext(ctx,
		`UPDATE host_keys SET last_seen_at = ? WHERE id = ?`, fmtTime(s.now()), id)
	return err
}

// RevokeHostKey marks a trusted key as no longer trusted. This is the only way
// to clear a mismatch, and it is an explicit administrative action rather than
// something the connect path can do.
func (s *Store) RevokeHostKey(ctx context.Context, id string) error {
	res, err := s.write.ExecContext(ctx,
		`UPDATE host_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		fmtTime(s.now()), id)
	return affected(res, err)
}
