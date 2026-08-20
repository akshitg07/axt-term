package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The audit log is append-only. There is deliberately no update or delete method
// reachable from the API surface; PruneAudit exists for the admin CLI and is
// itself audited by its caller.

// RecordAudit appends one event.
//
// Failures are returned rather than swallowed so the caller can decide, but note
// that callers generally log-and-continue: refusing a user's action because the
// audit write failed would turn a logging problem into an outage.
func (s *Store) RecordAudit(ctx context.Context, e *AuditEvent) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = s.now()
	}
	if e.Severity == "" {
		e.Severity = SeverityInfo
	}
	detail := "{}"
	if len(e.Detail) > 0 {
		encoded, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("store: encode audit detail: %w", err)
		}
		detail = string(encoded)
	}
	res, err := s.write.ExecContext(ctx, `
		INSERT INTO audit_events (ts, user_id, username, host_id, host_snapshot, action,
			target, result, severity, client_ip, auth_session_id, detail_json, request_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fmtTime(e.Timestamp), nullIfEmpty(e.UserID), e.Username,
		nullIfEmpty(e.HostID), e.HostSnapshot, e.Action, e.Target,
		string(e.Result), string(e.Severity), e.ClientIP, e.AuthSessionID,
		detail, e.RequestID)
	if err != nil {
		return mapWriteError(err)
	}
	if id, err := res.LastInsertId(); err == nil {
		e.ID = id
	}
	return nil
}

// AuditFilter narrows an audit query.
type AuditFilter struct {
	From     *time.Time
	To       *time.Time
	UserID   string
	HostID   string
	Action   string
	Result   AuditResult
	Severity AuditSeverity
	Query    string
	Limit    int
	Cursor   string // an id; results are strictly older
}

// ListAudit returns matching events newest first, plus a cursor for the next page.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]*AuditEvent, string, error) {
	var (
		where []string
		args  []any
	)
	if f.From != nil {
		where = append(where, `ts >= ?`)
		args = append(args, fmtTime(*f.From))
	}
	if f.To != nil {
		where = append(where, `ts <= ?`)
		args = append(args, fmtTime(*f.To))
	}
	if f.UserID != "" {
		where = append(where, `user_id = ?`)
		args = append(args, f.UserID)
	}
	if f.HostID != "" {
		where = append(where, `host_id = ?`)
		args = append(args, f.HostID)
	}
	if f.Action != "" {
		// Prefix matching so "session." selects every session event.
		where = append(where, `action LIKE ?`)
		args = append(args, f.Action+"%")
	}
	if f.Result != "" {
		where = append(where, `result = ?`)
		args = append(args, string(f.Result))
	}
	if f.Severity != "" {
		where = append(where, `severity = ?`)
		args = append(args, string(f.Severity))
	}
	if f.Query != "" {
		like := "%" + strings.ToLower(f.Query) + "%"
		where = append(where, `(LOWER(username) LIKE ? OR LOWER(target) LIKE ?
			OR LOWER(host_snapshot) LIKE ? OR LOWER(detail_json) LIKE ?)`)
		args = append(args, like, like, like, like)
	}
	if f.Cursor != "" {
		id, err := strconv.ParseInt(f.Cursor, 10, 64)
		if err != nil {
			return nil, "", fmt.Errorf("store: invalid audit cursor %q", f.Cursor)
		}
		where = append(where, `id < ?`)
		args = append(args, id)
	}

	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	query := `SELECT id, ts, user_id, username, host_id, host_snapshot, action, target,
		result, severity, client_ip, auth_session_id, detail_json, request_id
		FROM audit_events`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	// Ordering by id rather than ts gives a stable cursor even when several
	// events share a timestamp.
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit+1)

	rows, err := s.read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()

	out := []*AuditEvent{}
	for rows.Next() {
		var (
			e      AuditEvent
			userID sql.NullString
			hostID sql.NullString
			ts     string
			detail string
		)
		if err := rows.Scan(&e.ID, &ts, &userID, &e.Username, &hostID, &e.HostSnapshot,
			&e.Action, &e.Target, &e.Result, &e.Severity, &e.ClientIP,
			&e.AuthSessionID, &detail, &e.RequestID); err != nil {
			return nil, "", err
		}
		e.UserID = str(userID)
		e.HostID = str(hostID)
		e.Timestamp = parseTime(ts)
		if detail != "" && detail != "{}" {
			_ = json.Unmarshal([]byte(detail), &e.Detail)
		}
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}

	next := ""
	if len(out) > limit {
		next = strconv.FormatInt(out[limit-1].ID, 10)
		out = out[:limit]
	}
	return out, next, nil
}

// AuditActions returns the distinct action keys present, for filter menus.
func (s *Store) AuditActions(ctx context.Context) ([]string, error) {
	rows, err := s.read.QueryContext(ctx, `SELECT DISTINCT action FROM audit_events ORDER BY action`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []string{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// PruneAudit deletes events older than cutoff. Admin CLI only.
func (s *Store) PruneAudit(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.write.ExecContext(ctx, `DELETE FROM audit_events WHERE ts < ?`, fmtTime(cutoff))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// CountAudit reports the total number of events, for the admin overview.
func (s *Store) CountAudit(ctx context.Context) (int64, error) {
	var n int64
	err := s.read.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&n)
	return n, err
}
