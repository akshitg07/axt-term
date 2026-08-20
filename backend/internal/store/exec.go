package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// Multi-host command jobs. Results are persisted rather than held in memory
// because reviewing and exporting them afterwards is the point of the feature:
// a run across fifty hosts is evidence, not just a transient view.

// CreateExecJob inserts a job and its pending host rows.
func (s *Store) CreateExecJob(ctx context.Context, job *ExecJob, hosts []*Host) error {
	if job.CreatedAt.IsZero() {
		job.CreatedAt = s.now()
	}
	if job.Status == "" {
		job.Status = ExecRunning
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO exec_jobs (id, user_id, command, mode, concurrency, timeout_s,
				stop_on_error, status, risk_ack, created_at, finished_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			job.ID, nullIfEmpty(job.UserID), job.Command, string(job.Mode), job.Concurrency,
			job.TimeoutS, boolInt(job.StopOnError), string(job.Status), job.RiskAck,
			fmtTime(job.CreatedAt))
		if err != nil {
			return mapWriteError(err)
		}
		for _, h := range hosts {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO exec_job_hosts (job_id, host_id, host_label, status)
				VALUES (?, ?, ?, 'pending')`, job.ID, h.ID, h.Label()); err != nil {
				return mapWriteError(err)
			}
		}
		return nil
	})
}

// StartExecHost marks one host's execution as begun.
func (s *Store) StartExecHost(ctx context.Context, jobID, hostID string) error {
	_, err := s.write.ExecContext(ctx, `
		UPDATE exec_job_hosts SET status = 'running', started_at = ?
		WHERE job_id = ? AND host_id = ?`, fmtTime(s.now()), jobID, hostID)
	return err
}

// FinishExecHost records one host's outcome.
func (s *Store) FinishExecHost(ctx context.Context, r *ExecJobHost) error {
	var exitCode any
	if r.ExitCode != nil {
		exitCode = *r.ExitCode
	}
	_, err := s.write.ExecContext(ctx, `
		UPDATE exec_job_hosts
		SET status = ?, exit_code = ?, stdout = ?, stderr = ?, truncated = ?, error = ?,
		    duration_ms = ?, finished_at = ?
		WHERE job_id = ? AND host_id = ?`,
		string(r.Status), exitCode, r.Stdout, r.Stderr, boolInt(r.Truncated), r.Error,
		r.DurationMS, fmtTime(s.now()), r.JobID, r.HostID)
	return err
}

// CancelPendingExecHosts marks hosts that never ran as cancelled.
//
// Reporting honestly which hosts already executed is essential after a
// cancellation: "cancelled" must not imply "nothing happened".
func (s *Store) CancelPendingExecHosts(ctx context.Context, jobID string) (int, error) {
	res, err := s.write.ExecContext(ctx, `
		UPDATE exec_job_hosts SET status = 'cancelled', finished_at = ?
		WHERE job_id = ? AND status IN ('pending', 'running')`, fmtTime(s.now()), jobID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// FinishExecJob records a job's terminal state.
func (s *Store) FinishExecJob(ctx context.Context, jobID string, status ExecJobStatus) error {
	res, err := s.write.ExecContext(ctx,
		`UPDATE exec_jobs SET status = ?, finished_at = ? WHERE id = ?`,
		string(status), fmtTime(s.now()), jobID)
	return affected(res, err)
}

// ExecJobByID loads a job with every host result.
func (s *Store) ExecJobByID(ctx context.Context, id string) (*ExecJob, error) {
	var (
		job         ExecJob
		userID      sql.NullString
		stopOnError int
		createdAt   string
		finishedAt  sql.NullString
	)
	err := s.read.QueryRowContext(ctx, `
		SELECT id, user_id, command, mode, concurrency, timeout_s, stop_on_error,
		       status, risk_ack, created_at, finished_at
		FROM exec_jobs WHERE id = ?`, id).
		Scan(&job.ID, &userID, &job.Command, &job.Mode, &job.Concurrency, &job.TimeoutS,
			&stopOnError, &job.Status, &job.RiskAck, &createdAt, &finishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	job.UserID = str(userID)
	job.StopOnError = stopOnError == 1
	job.CreatedAt = parseTime(createdAt)
	job.FinishedAt = timePtr(finishedAt)

	hosts, err := s.execJobHosts(ctx, id)
	if err != nil {
		return nil, err
	}
	job.Hosts = hosts
	return &job, nil
}

func (s *Store) execJobHosts(ctx context.Context, jobID string) ([]ExecJobHost, error) {
	rows, err := s.read.QueryContext(ctx, `
		SELECT job_id, host_id, host_label, status, exit_code, stdout, stderr,
		       truncated, error, duration_ms, started_at, finished_at
		FROM exec_job_hosts WHERE job_id = ?
		ORDER BY CASE status
			WHEN 'failed' THEN 0 WHEN 'timeout' THEN 1 WHEN 'running' THEN 2
			WHEN 'pending' THEN 3 WHEN 'cancelled' THEN 4 ELSE 5 END,
			host_label COLLATE NOCASE`, jobID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []ExecJobHost{}
	for rows.Next() {
		var (
			r          ExecJobHost
			exitCode   sql.NullInt64
			truncated  int
			startedAt  sql.NullString
			finishedAt sql.NullString
		)
		if err := rows.Scan(&r.JobID, &r.HostID, &r.HostLabel, &r.Status, &exitCode,
			&r.Stdout, &r.Stderr, &truncated, &r.Error, &r.DurationMS,
			&startedAt, &finishedAt); err != nil {
			return nil, err
		}
		r.ExitCode = intPtr(exitCode)
		r.Truncated = truncated == 1
		r.StartedAt = timePtr(startedAt)
		r.FinishedAt = timePtr(finishedAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListExecJobs returns a user's recent jobs without host detail.
func (s *Store) ListExecJobs(ctx context.Context, userID string, limit int) ([]*ExecJob, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.read.QueryContext(ctx, `
		SELECT id, user_id, command, mode, concurrency, timeout_s, stop_on_error,
		       status, risk_ack, created_at, finished_at
		FROM exec_jobs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []*ExecJob{}
	for rows.Next() {
		var (
			job         ExecJob
			userIDCol   sql.NullString
			stopOnError int
			createdAt   string
			finishedAt  sql.NullString
		)
		if err := rows.Scan(&job.ID, &userIDCol, &job.Command, &job.Mode, &job.Concurrency,
			&job.TimeoutS, &stopOnError, &job.Status, &job.RiskAck, &createdAt, &finishedAt); err != nil {
			return nil, err
		}
		job.UserID = str(userIDCol)
		job.StopOnError = stopOnError == 1
		job.CreatedAt = parseTime(createdAt)
		job.FinishedAt = timePtr(finishedAt)
		out = append(out, &job)
	}
	return out, rows.Err()
}

// SweepRunningExecJobs marks jobs left running by a restart as failed.
func (s *Store) SweepRunningExecJobs(ctx context.Context, reason string) (int, error) {
	var swept int
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			UPDATE exec_job_hosts SET status = 'cancelled', error = ?, finished_at = ?
			WHERE status IN ('pending', 'running')`, reason, fmtTime(s.now())); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE exec_jobs SET status = 'failed', finished_at = ?
			WHERE status = 'running'`, fmtTime(s.now()))
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		swept = int(n)
		return err
	})
	return swept, err
}

// --------------------------------------------------------------- discovery ---

// CreateDiscoveryScan records the start of a scan.
func (s *Store) CreateDiscoveryScan(ctx context.Context, id, userID, cidr, ports string) error {
	_, err := s.write.ExecContext(ctx, `
		INSERT INTO discovery_scans (id, user_id, cidr, ports, status, found_count, started_at, finished_at)
		VALUES (?, ?, ?, ?, 'running', 0, ?, NULL)`,
		id, nullIfEmpty(userID), cidr, ports, fmtTime(s.now()))
	return mapWriteError(err)
}

// FinishDiscoveryScan records a scan's completion.
func (s *Store) FinishDiscoveryScan(ctx context.Context, id, status string, found int) error {
	res, err := s.write.ExecContext(ctx,
		`UPDATE discovery_scans SET status = ?, found_count = ?, finished_at = ? WHERE id = ?`,
		status, found, fmtTime(s.now()), id)
	return affected(res, err)
}

// AddDiscoveredHost records one responding address. No authentication is ever
// attempted during discovery; only a banner is read.
func (s *Store) AddDiscoveredHost(ctx context.Context, id, scanID, ip, hostname, mac, portsJSON, banner, osHint string) error {
	_, err := s.write.ExecContext(ctx, `
		INSERT INTO discovered_hosts (id, scan_id, ip, hostname, mac, open_ports_json,
			ssh_banner, os_hint, imported_host_id, seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
		id, scanID, ip, hostname, mac, portsJSON, banner, osHint, fmtTime(s.now()))
	return mapWriteError(err)
}

// MarkDiscoveredImported links a discovered address to the host created from it.
func (s *Store) MarkDiscoveredImported(ctx context.Context, discoveredID, hostID string) error {
	res, err := s.write.ExecContext(ctx,
		`UPDATE discovered_hosts SET imported_host_id = ? WHERE id = ?`, hostID, discoveredID)
	return affected(res, err)
}

// --------------------------------------------------------------- searching ---

// SearchResult is one hit from the unified search.
type SearchResult struct {
	Kind     string `json:"kind"` // host, folder, snippet, tag, workspace, session
	ID       string `json:"id"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// Search looks across hosts, folders, tags, snippets, and workspaces at once.
//
// One query per kind rather than a UNION: the result shapes differ, the row
// counts are small, and keeping them separate makes per-kind ranking possible.
func (s *Store) Search(ctx context.Context, userID, query string, limit int) ([]SearchResult, error) {
	if strings.TrimSpace(query) == "" {
		return []SearchResult{}, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	like := "%" + strings.ToLower(query) + "%"
	out := []SearchResult{}

	appendRows := func(rows *sql.Rows, kind string) error {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			r := SearchResult{Kind: kind}
			if kind == "host" {
				if err := rows.Scan(&r.ID, &r.Title, &r.Subtitle, &r.Protocol); err != nil {
					return err
				}
			} else if err := rows.Scan(&r.ID, &r.Title, &r.Subtitle); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	}

	hostRows, err := s.read.QueryContext(ctx, `
		SELECT id, name, hostname, protocol FROM hosts
		WHERE LOWER(name) LIKE ? OR LOWER(hostname) LIKE ? OR LOWER(notes) LIKE ?
		ORDER BY is_favorite DESC, name COLLATE NOCASE LIMIT ?`, like, like, like, limit)
	if err != nil {
		return nil, err
	}
	if err := appendRows(hostRows, "host"); err != nil {
		return nil, err
	}

	folderRows, err := s.read.QueryContext(ctx, `
		SELECT id, name, '' FROM folders WHERE LOWER(name) LIKE ?
		ORDER BY name COLLATE NOCASE LIMIT ?`, like, limit)
	if err != nil {
		return nil, err
	}
	if err := appendRows(folderRows, "folder"); err != nil {
		return nil, err
	}

	tagRows, err := s.read.QueryContext(ctx, `
		SELECT id, name, '' FROM tags WHERE LOWER(name) LIKE ?
		ORDER BY name COLLATE NOCASE LIMIT ?`, like, limit)
	if err != nil {
		return nil, err
	}
	if err := appendRows(tagRows, "tag"); err != nil {
		return nil, err
	}

	snippetRows, err := s.read.QueryContext(ctx, `
		SELECT id, name, description FROM snippets
		WHERE LOWER(name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(body) LIKE ?
		ORDER BY is_favorite DESC, use_count DESC LIMIT ?`, like, like, like, limit)
	if err != nil {
		return nil, err
	}
	if err := appendRows(snippetRows, "snippet"); err != nil {
		return nil, err
	}

	workspaceRows, err := s.read.QueryContext(ctx, `
		SELECT id, name, '' FROM workspaces WHERE user_id = ? AND LOWER(name) LIKE ?
		ORDER BY name COLLATE NOCASE LIMIT ?`, userID, like, limit)
	if err != nil {
		return nil, err
	}
	if err := appendRows(workspaceRows, "workspace"); err != nil {
		return nil, err
	}

	return out, nil
}
