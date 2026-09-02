package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// -------------------------------------------------------- session records ---

const sessionColumns = `id, user_id, host_id, host_snapshot, protocol, status, client_ip,
	started_at, ended_at, bytes_in, bytes_out, recording_path, exit_reason`

func scanSessionRecord(row rowScanner) (*SessionRecord, error) {
	var (
		r         SessionRecord
		userID    sql.NullString
		hostID    sql.NullString
		startedAt string
		endedAt   sql.NullString
	)
	err := row.Scan(&r.ID, &userID, &hostID, &r.HostSnapshot, &r.Protocol, &r.Status,
		&r.ClientIP, &startedAt, &endedAt, &r.BytesIn, &r.BytesOut,
		&r.RecordingPath, &r.ExitReason)
	if err != nil {
		return nil, err
	}
	r.UserID = str(userID)
	r.HostID = str(hostID)
	r.StartedAt = parseTime(startedAt)
	r.EndedAt = timePtr(endedAt)
	return &r, nil
}

// CreateSessionRecord opens a history entry for a session.
func (s *Store) CreateSessionRecord(ctx context.Context, r *SessionRecord) error {
	if r.StartedAt.IsZero() {
		r.StartedAt = s.now()
	}
	_, err := s.write.ExecContext(ctx,
		`INSERT INTO session_records (`+sessionColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, nullIfEmpty(r.UserID), nullIfEmpty(r.HostID), r.HostSnapshot,
		string(r.Protocol), string(r.Status), r.ClientIP, fmtTime(r.StartedAt),
		fmtTimePtr(r.EndedAt), r.BytesIn, r.BytesOut, r.RecordingPath, r.ExitReason)
	return mapWriteError(err)
}

// UpdateSessionStatus records a state transition.
func (s *Store) UpdateSessionStatus(ctx context.Context, id string, status SessionStatus, exitReason string) error {
	_, err := s.write.ExecContext(ctx,
		`UPDATE session_records SET status = ?, exit_reason = ? WHERE id = ?`,
		string(status), exitReason, id)
	return err
}

// CloseSessionRecord finalises a history entry with byte counts.
func (s *Store) CloseSessionRecord(ctx context.Context, id string, status SessionStatus, exitReason string, bytesIn, bytesOut int64) error {
	_, err := s.write.ExecContext(ctx, `
		UPDATE session_records
		SET status = ?, exit_reason = ?, bytes_in = ?, bytes_out = ?, ended_at = ?
		WHERE id = ?`,
		string(status), exitReason, bytesIn, bytesOut, fmtTime(s.now()), id)
	return err
}

// SetSessionRecording stores the path of a recording file.
func (s *Store) SetSessionRecording(ctx context.Context, id, path string) error {
	_, err := s.write.ExecContext(ctx,
		`UPDATE session_records SET recording_path = ? WHERE id = ?`, path, id)
	return err
}

// SessionRecordByID loads one history entry.
func (s *Store) SessionRecordByID(ctx context.Context, id string) (*SessionRecord, error) {
	r, err := scanSessionRecord(s.read.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM session_records WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// RecentSessions returns a user's most recent sessions, one entry per host.
//
// Grouping by host is what makes the Recent panel useful: twenty reconnects to
// the same box should occupy one row, not twenty.
func (s *Store) RecentSessions(ctx context.Context, userID string, limit int) ([]*SessionRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := s.read.QueryContext(ctx, `
		SELECT `+qualify(sessionColumns, "sr")+`, COALESCE(h.name, '')
		FROM session_records sr
		LEFT JOIN hosts h ON h.id = sr.host_id
		WHERE sr.user_id = ?
		  AND sr.started_at = (
			SELECT MAX(inner_sr.started_at) FROM session_records inner_sr
			WHERE inner_sr.user_id = sr.user_id
			  AND COALESCE(inner_sr.host_id, inner_sr.host_snapshot) =
			      COALESCE(sr.host_id, sr.host_snapshot)
		  )
		ORDER BY sr.started_at DESC
		LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*SessionRecord{}
	for rows.Next() {
		var (
			r         SessionRecord
			userIDCol sql.NullString
			hostID    sql.NullString
			startedAt string
			endedAt   sql.NullString
			hostName  string
		)
		if err := rows.Scan(&r.ID, &userIDCol, &hostID, &r.HostSnapshot, &r.Protocol,
			&r.Status, &r.ClientIP, &startedAt, &endedAt, &r.BytesIn, &r.BytesOut,
			&r.RecordingPath, &r.ExitReason, &hostName); err != nil {
			return nil, err
		}
		r.UserID = str(userIDCol)
		r.HostID = str(hostID)
		r.StartedAt = parseTime(startedAt)
		r.EndedAt = timePtr(endedAt)
		r.HostName = hostName
		out = append(out, &r)
	}
	return out, rows.Err()
}

// DeleteSessionRecord removes one history entry belonging to a user.
//
// Scoped by user_id in the statement rather than checked beforehand, so a
// mismatched id cannot delete somebody else's history through a race between the
// check and the delete. A row that does not match reports ErrNotFound, which is
// also what a caller sees for an id that never existed -- the two are the same
// thing from outside.
//
// History is a convenience list, not an audit trail: the audit log is separate,
// append-only, and unaffected by this. Curating what appears under Recent must not
// be a way to erase evidence, and it is not.
func (s *Store) DeleteSessionRecord(ctx context.Context, userID, id string) error {
	res, err := s.write.ExecContext(ctx,
		`DELETE FROM session_records WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSessionRecordsForUser clears a user's session history.
//
// Live sessions are left alone: their rows are rewritten when they close, and
// clearing the list must not appear to disconnect anything.
func (s *Store) DeleteSessionRecordsForUser(ctx context.Context, userID string) (int, error) {
	res, err := s.write.ExecContext(ctx, `
		DELETE FROM session_records
		WHERE user_id = ? AND status NOT IN ('connecting', 'connected')`, userID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// SweepOpenSessions marks sessions left open by a crash or restart as closed.
//
// Called at startup: a session row stuck in "connected" with no live PTY behind
// it would misreport history and inflate any session count derived from it.
func (s *Store) SweepOpenSessions(ctx context.Context, reason string) (int, error) {
	res, err := s.write.ExecContext(ctx, `
		UPDATE session_records
		SET status = 'closed', exit_reason = ?, ended_at = ?
		WHERE status IN ('connecting', 'connected') AND ended_at IS NULL`,
		reason, fmtTime(s.now()))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// ------------------------------------------------------------- transfers ---

const transferColumns = `id, user_id, host_id, direction, remote_path, display_name,
	size_bytes, transferred_bytes, status, error, speed_bps, retry_count,
	queued_at, started_at, finished_at`

func scanTransfer(row rowScanner) (*Transfer, error) {
	var (
		t          Transfer
		userID     sql.NullString
		hostID     sql.NullString
		size       sql.NullInt64
		queuedAt   string
		startedAt  sql.NullString
		finishedAt sql.NullString
	)
	err := row.Scan(&t.ID, &userID, &hostID, &t.Direction, &t.RemotePath, &t.DisplayName,
		&size, &t.TransferredBytes, &t.Status, &t.Error, &t.SpeedBPS, &t.RetryCount,
		&queuedAt, &startedAt, &finishedAt)
	if err != nil {
		return nil, err
	}
	t.UserID = str(userID)
	t.HostID = str(hostID)
	t.SizeBytes = int64Ptr(size)
	t.QueuedAt = parseTime(queuedAt)
	t.StartedAt = timePtr(startedAt)
	t.FinishedAt = timePtr(finishedAt)
	return &t, nil
}

// CreateTransfer enqueues a transfer.
func (s *Store) CreateTransfer(ctx context.Context, t *Transfer) error {
	if t.QueuedAt.IsZero() {
		t.QueuedAt = s.now()
	}
	if t.Status == "" {
		t.Status = TransferQueued
	}
	var size any
	if t.SizeBytes != nil {
		size = *t.SizeBytes
	}
	_, err := s.write.ExecContext(ctx,
		`INSERT INTO transfers (`+transferColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, nullIfEmpty(t.UserID), nullIfEmpty(t.HostID), string(t.Direction),
		t.RemotePath, t.DisplayName, size, t.TransferredBytes, string(t.Status),
		t.Error, t.SpeedBPS, t.RetryCount, fmtTime(t.QueuedAt),
		fmtTimePtr(t.StartedAt), fmtTimePtr(t.FinishedAt))
	return mapWriteError(err)
}

// TransferByID loads one transfer.
func (s *Store) TransferByID(ctx context.Context, id string) (*Transfer, error) {
	t, err := scanTransfer(s.read.QueryRowContext(ctx,
		`SELECT `+transferColumns+` FROM transfers WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// TransferFilter narrows a transfer listing.
type TransferFilter struct {
	UserID string
	Status TransferStatus
	Limit  int
	Cursor string // a queued_at value; results are strictly older
}

// ListTransfers returns transfers newest first, with host names attached.
func (s *Store) ListTransfers(ctx context.Context, f TransferFilter) ([]*Transfer, error) {
	var (
		where []string
		args  []any
	)
	if f.UserID != "" {
		where = append(where, `t.user_id = ?`)
		args = append(args, f.UserID)
	}
	if f.Status != "" {
		where = append(where, `t.status = ?`)
		args = append(args, string(f.Status))
	}
	if f.Cursor != "" {
		where = append(where, `t.queued_at < ?`)
		args = append(args, f.Cursor)
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	query := `SELECT ` + qualify(transferColumns, "t") + `, COALESCE(h.name, '')
		FROM transfers t LEFT JOIN hosts h ON h.id = t.host_id`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += ` ORDER BY t.queued_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*Transfer{}
	for rows.Next() {
		var (
			t          Transfer
			userID     sql.NullString
			hostID     sql.NullString
			size       sql.NullInt64
			queuedAt   string
			startedAt  sql.NullString
			finishedAt sql.NullString
			hostName   string
		)
		if err := rows.Scan(&t.ID, &userID, &hostID, &t.Direction, &t.RemotePath,
			&t.DisplayName, &size, &t.TransferredBytes, &t.Status, &t.Error,
			&t.SpeedBPS, &t.RetryCount, &queuedAt, &startedAt, &finishedAt, &hostName); err != nil {
			return nil, err
		}
		t.UserID = str(userID)
		t.HostID = str(hostID)
		t.SizeBytes = int64Ptr(size)
		t.QueuedAt = parseTime(queuedAt)
		t.StartedAt = timePtr(startedAt)
		t.FinishedAt = timePtr(finishedAt)
		t.HostName = hostName
		out = append(out, &t)
	}
	return out, rows.Err()
}

// ClaimNextTransfer atomically marks the oldest queued transfer active.
//
// The UPDATE ... WHERE status = 'queued' is the claim: with a single writer
// connection, two workers cannot both win the same row.
func (s *Store) ClaimNextTransfer(ctx context.Context) (*Transfer, error) {
	var claimed *Transfer
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var id string
		err := tx.QueryRowContext(ctx,
			`SELECT id FROM transfers WHERE status = 'queued' ORDER BY queued_at LIMIT 1`).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE transfers SET status = 'active', started_at = ? WHERE id = ? AND status = 'queued'`,
			fmtTime(s.now()), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		claimed, err = scanTransfer(tx.QueryRowContext(ctx,
			`SELECT `+transferColumns+` FROM transfers WHERE id = ?`, id))
		return err
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

// UpdateTransferProgress records bytes moved and current speed.
func (s *Store) UpdateTransferProgress(ctx context.Context, id string, transferred, speedBPS int64) error {
	_, err := s.write.ExecContext(ctx,
		`UPDATE transfers SET transferred_bytes = ?, speed_bps = ? WHERE id = ?`,
		transferred, speedBPS, id)
	return err
}

// FinishTransfer records a terminal state.
func (s *Store) FinishTransfer(ctx context.Context, id string, status TransferStatus, transferred int64, errMsg string) error {
	_, err := s.write.ExecContext(ctx, `
		UPDATE transfers
		SET status = ?, transferred_bytes = ?, error = ?, finished_at = ?, speed_bps = 0
		WHERE id = ?`,
		string(status), transferred, errMsg, fmtTime(s.now()), id)
	return err
}

// SetTransferSize records the size once it is known.
func (s *Store) SetTransferSize(ctx context.Context, id string, size int64) error {
	_, err := s.write.ExecContext(ctx, `UPDATE transfers SET size_bytes = ? WHERE id = ?`, size, id)
	return err
}

// RequeueTransfer resets a failed or interrupted transfer for another attempt.
func (s *Store) RequeueTransfer(ctx context.Context, id string) error {
	res, err := s.write.ExecContext(ctx, `
		UPDATE transfers
		SET status = 'queued', error = '', transferred_bytes = 0, speed_bps = 0,
		    retry_count = retry_count + 1, queued_at = ?, started_at = NULL, finished_at = NULL
		WHERE id = ? AND status IN ('failed', 'cancelled', 'interrupted')`,
		fmtTime(s.now()), id)
	return affected(res, err)
}

// SweepActiveTransfers marks transfers that were in flight at shutdown as
// interrupted.
//
// Called at startup. Without it the UI would show a progress bar that can never
// move again; marking them interrupted lets it offer Retry honestly.
func (s *Store) SweepActiveTransfers(ctx context.Context, reason string) (int, error) {
	res, err := s.write.ExecContext(ctx, `
		UPDATE transfers SET status = 'interrupted', error = ?, finished_at = ?, speed_bps = 0
		WHERE status = 'active'`, reason, fmtTime(s.now()))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// DeleteTransfer removes a history entry.
func (s *Store) DeleteTransfer(ctx context.Context, id string) error {
	res, err := s.write.ExecContext(ctx,
		`DELETE FROM transfers WHERE id = ? AND status <> 'active'`, id)
	return affected(res, err)
}

// ClearCompletedTransfers removes finished entries for a user.
func (s *Store) ClearCompletedTransfers(ctx context.Context, userID string) (int, error) {
	res, err := s.write.ExecContext(ctx,
		`DELETE FROM transfers WHERE user_id = ? AND status IN ('completed', 'cancelled')`, userID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// ------------------------------------------------- tunnels and workspaces ---

const tunnelColumns = `id, name, host_id, kind, listen_host, listen_port,
	target_host, target_port, autostart, created_by, created_at, updated_at`

func scanTunnel(row rowScanner) (*Tunnel, error) {
	var (
		t         Tunnel
		createdBy sql.NullString
		autostart int
		createdAt string
		updatedAt string
	)
	err := row.Scan(&t.ID, &t.Name, &t.HostID, &t.Kind, &t.ListenHost, &t.ListenPort,
		&t.TargetHost, &t.TargetPort, &autostart, &createdBy, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	t.Autostart = autostart == 1
	t.CreatedBy = str(createdBy)
	t.CreatedAt = parseTime(createdAt)
	t.UpdatedAt = parseTime(updatedAt)
	return &t, nil
}

// ListTunnels returns every stored tunnel definition.
func (s *Store) ListTunnels(ctx context.Context) ([]*Tunnel, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT `+tunnelColumns+` FROM tunnels ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*Tunnel{}
	for rows.Next() {
		t, err := scanTunnel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TunnelByID loads one tunnel definition.
func (s *Store) TunnelByID(ctx context.Context, id string) (*Tunnel, error) {
	t, err := scanTunnel(s.read.QueryRowContext(ctx,
		`SELECT `+tunnelColumns+` FROM tunnels WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// CreateTunnel stores a tunnel definition.
func (s *Store) CreateTunnel(ctx context.Context, t *Tunnel) error {
	now := s.now()
	t.CreatedAt, t.UpdatedAt = now, now
	_, err := s.write.ExecContext(ctx,
		`INSERT INTO tunnels (`+tunnelColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.HostID, string(t.Kind), t.ListenHost, t.ListenPort,
		t.TargetHost, t.TargetPort, boolInt(t.Autostart), nullIfEmpty(t.CreatedBy),
		fmtTime(t.CreatedAt), fmtTime(t.UpdatedAt))
	return mapWriteError(err)
}

// UpdateTunnel replaces a tunnel definition.
func (s *Store) UpdateTunnel(ctx context.Context, t *Tunnel) error {
	t.UpdatedAt = s.now()
	res, err := s.write.ExecContext(ctx, `
		UPDATE tunnels SET name = ?, host_id = ?, kind = ?, listen_host = ?, listen_port = ?,
			target_host = ?, target_port = ?, autostart = ?, updated_at = ?
		WHERE id = ?`,
		t.Name, t.HostID, string(t.Kind), t.ListenHost, t.ListenPort,
		t.TargetHost, t.TargetPort, boolInt(t.Autostart), fmtTime(t.UpdatedAt), t.ID)
	return affected(res, err)
}

// DeleteTunnel removes a tunnel definition.
func (s *Store) DeleteTunnel(ctx context.Context, id string) error {
	res, err := s.write.ExecContext(ctx, `DELETE FROM tunnels WHERE id = ?`, id)
	return affected(res, err)
}

// ListWorkspaces returns a user's saved layouts.
func (s *Store) ListWorkspaces(ctx context.Context, userID string) ([]*Workspace, error) {
	rows, err := s.read.QueryContext(ctx, `
		SELECT id, user_id, name, layout_json, is_default, created_at, updated_at
		FROM workspaces WHERE user_id = ? ORDER BY is_default DESC, name COLLATE NOCASE`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*Workspace{}
	for rows.Next() {
		var (
			w         Workspace
			isDefault int
			createdAt string
			updatedAt string
		)
		if err := rows.Scan(&w.ID, &w.UserID, &w.Name, &w.Layout, &isDefault,
			&createdAt, &updatedAt); err != nil {
			return nil, err
		}
		w.IsDefault = isDefault == 1
		w.CreatedAt = parseTime(createdAt)
		w.UpdatedAt = parseTime(updatedAt)
		out = append(out, &w)
	}
	return out, rows.Err()
}

// SaveWorkspace inserts or replaces a layout by name.
func (s *Store) SaveWorkspace(ctx context.Context, w *Workspace) error {
	now := s.now()
	if w.CreatedAt.IsZero() {
		w.CreatedAt = now
	}
	w.UpdatedAt = now
	return s.tx(ctx, func(tx *sql.Tx) error {
		if w.IsDefault {
			if _, err := tx.ExecContext(ctx,
				`UPDATE workspaces SET is_default = 0 WHERE user_id = ?`, w.UserID); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO workspaces (id, user_id, name, layout_json, is_default, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(user_id, name) DO UPDATE SET
				layout_json = excluded.layout_json,
				is_default = excluded.is_default,
				updated_at = excluded.updated_at`,
			w.ID, w.UserID, w.Name, w.Layout, boolInt(w.IsDefault),
			fmtTime(w.CreatedAt), fmtTime(w.UpdatedAt))
		return mapWriteError(err)
	})
}

// DeleteWorkspace removes a saved layout.
func (s *Store) DeleteWorkspace(ctx context.Context, userID, id string) error {
	res, err := s.write.ExecContext(ctx,
		`DELETE FROM workspaces WHERE id = ? AND user_id = ?`, id, userID)
	return affected(res, err)
}

// PurgeOldSessionRecords deletes history older than cutoff.
func (s *Store) PurgeOldSessionRecords(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.write.ExecContext(ctx,
		`DELETE FROM session_records WHERE started_at < ? AND ended_at IS NOT NULL`,
		fmtTime(cutoff))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
