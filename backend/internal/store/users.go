package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const userColumns = `id, username, email, display_name, password_hash, totp_secret_enc,
	is_active, must_change_password, failed_login_count, locked_until,
	last_login_at, created_at, updated_at`

// rowScanner is satisfied by both *sql.Row and *sql.Rows, so single-row and
// multi-row reads share one scan function.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*User, error) {
	var (
		u            User
		totp         []byte
		lockedUntil  sql.NullString
		lastLoginAt  sql.NullString
		createdAt    string
		updatedAt    string
		isActive     int
		mustChangePw int
	)
	err := row.Scan(
		&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &totp,
		&isActive, &mustChangePw, &u.FailedLoginCount, &lockedUntil,
		&lastLoginAt, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	u.TOTPSecretEnc = totp
	u.IsActive = isActive == 1
	u.MustChangePassword = mustChangePw == 1
	u.LockedUntil = timePtr(lockedUntil)
	u.LastLoginAt = timePtr(lastLoginAt)
	u.CreatedAt = parseTime(createdAt)
	u.UpdatedAt = parseTime(updatedAt)
	return &u, nil
}

// CreateUser inserts a user and assigns roles.
func (s *Store) CreateUser(ctx context.Context, u *User, roleNames []string) error {
	now := s.now()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now

	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO users (id, username, email, display_name, password_hash, totp_secret_enc,
				is_active, must_change_password, failed_login_count, locked_until,
				last_login_at, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)`,
			u.ID, u.Username, u.Email, u.DisplayName, u.PasswordHash, u.TOTPSecretEnc,
			boolInt(u.IsActive), boolInt(u.MustChangePassword),
			fmtTime(u.CreatedAt), fmtTime(u.UpdatedAt),
		)
		if err != nil {
			return mapWriteError(err)
		}
		return assignRolesTx(ctx, tx, u.ID, roleNames)
	})
}

func assignRolesTx(ctx context.Context, tx *sql.Tx, userID string, roleNames []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, name := range roleNames {
		var roleID string
		err := tx.QueryRowContext(ctx, `SELECT id FROM roles WHERE name = ?`, name).Scan(&roleID)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: role %q", ErrNotFound, name)
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`, userID, roleID); err != nil {
			return mapWriteError(err)
		}
	}
	return nil
}

// UserByUsername loads a user by name. Lookup is case-insensitive because
// usernames are stored COLLATE NOCASE.
func (s *Store) UserByUsername(ctx context.Context, username string) (*User, error) {
	row := s.read.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE username = ?`, username)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if u.Roles, err = s.userRoleNames(ctx, u.ID); err != nil {
		return nil, err
	}
	return u, nil
}

// UserByID loads a user.
func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	row := s.read.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if u.Roles, err = s.userRoleNames(ctx, u.ID); err != nil {
		return nil, err
	}
	return u, nil
}

// ListUsers returns every account, newest first.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT `+userColumns+` FROM users ORDER BY username COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, u := range out {
		if u.Roles, err = s.userRoleNames(ctx, u.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// CountUsers reports how many accounts exist, used to detect first-run setup.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.read.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) userRoleNames(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.read.QueryContext(ctx, `
		SELECT r.name FROM roles r
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = ?
		ORDER BY r.name`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	names := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// UserPermissions returns the union of permissions across a user's roles.
func (s *Store) UserPermissions(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.read.QueryContext(ctx, `
		SELECT DISTINCT rp.permission_key
		FROM role_permissions rp
		JOIN user_roles ur ON ur.role_id = rp.role_id
		WHERE ur.user_id = ?
		ORDER BY rp.permission_key`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	perms := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// UpdateUserProfile changes the mutable, non-security fields.
func (s *Store) UpdateUserProfile(ctx context.Context, id, email, displayName string, isActive bool) error {
	res, err := s.write.ExecContext(ctx, `
		UPDATE users SET email = ?, display_name = ?, is_active = ?, updated_at = ?
		WHERE id = ?`,
		email, displayName, boolInt(isActive), fmtTime(s.now()), id)
	return affected(res, err)
}

// SetUserRoles replaces a user's role assignments.
func (s *Store) SetUserRoles(ctx context.Context, userID string, roleNames []string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id = ?`, userID).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return ErrNotFound
		}
		return assignRolesTx(ctx, tx, userID, roleNames)
	})
}

// SetPassword stores a new hash and clears the forced-change flag.
func (s *Store) SetPassword(ctx context.Context, userID, hash string) error {
	res, err := s.write.ExecContext(ctx, `
		UPDATE users
		SET password_hash = ?, must_change_password = 0, failed_login_count = 0,
		    locked_until = NULL, updated_at = ?
		WHERE id = ?`, hash, fmtTime(s.now()), userID)
	return affected(res, err)
}

// RecordLoginSuccess resets the failure counter and stamps the login time.
func (s *Store) RecordLoginSuccess(ctx context.Context, userID string) error {
	now := s.now()
	_, err := s.write.ExecContext(ctx, `
		UPDATE users
		SET failed_login_count = 0, locked_until = NULL, last_login_at = ?, updated_at = ?
		WHERE id = ?`, fmtTime(now), fmtTime(now), userID)
	return err
}

// RecordLoginFailure increments the failure counter and locks the account once
// the threshold is reached.
//
// Lockout lives in the database rather than in memory so it survives a restart:
// an attacker who can trigger a crash should not thereby clear the counter.
func (s *Store) RecordLoginFailure(ctx context.Context, userID string, threshold int, lockFor time.Duration) (locked bool, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx,
			`SELECT failed_login_count FROM users WHERE id = ?`, userID).Scan(&count); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		count++
		now := s.now()

		if threshold > 0 && count >= threshold {
			until := now.Add(lockFor)
			locked = true
			_, err := tx.ExecContext(ctx, `
				UPDATE users SET failed_login_count = ?, locked_until = ?, updated_at = ?
				WHERE id = ?`, count, fmtTime(until), fmtTime(now), userID)
			return err
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE users SET failed_login_count = ?, updated_at = ? WHERE id = ?`,
			count, fmtTime(now), userID)
		return err
	})
	return locked, err
}

// SetMustChangePassword forces a password change at next login.
func (s *Store) SetMustChangePassword(ctx context.Context, userID string, must bool) error {
	res, err := s.write.ExecContext(ctx,
		`UPDATE users SET must_change_password = ?, updated_at = ? WHERE id = ?`,
		boolInt(must), fmtTime(s.now()), userID)
	return affected(res, err)
}

// DeleteUser removes an account and, by cascade, its sessions and settings.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	res, err := s.write.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return affected(res, err)
}

// ------------------------------------------------------------------- roles ---

// ListRoles returns every role with its permissions.
func (s *Store) ListRoles(ctx context.Context) ([]*Role, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT id, name, description, is_builtin FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []*Role
	for rows.Next() {
		var (
			r         Role
			isBuiltin int
		)
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &isBuiltin); err != nil {
			return nil, err
		}
		r.IsBuiltin = isBuiltin == 1
		out = append(out, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, r := range out {
		perms, err := s.rolePermissions(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		r.Permissions = perms
	}
	return out, nil
}

func (s *Store) rolePermissions(ctx context.Context, roleID string) ([]string, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT permission_key FROM role_permissions WHERE role_id = ? ORDER BY permission_key`, roleID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListPermissions returns the permission registry as stored.
func (s *Store) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := s.read.QueryContext(ctx, `SELECT key, description FROM permissions ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.Key, &p.Description); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------- auth sessions ---

// CreateAuthSession stores a browser session.
func (s *Store) CreateAuthSession(ctx context.Context, sess *AuthSession) error {
	_, err := s.write.ExecContext(ctx, `
		INSERT INTO auth_sessions (id, user_id, token_hash, csrf_hash, user_agent, ip,
			created_at, last_seen_at, expires_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		sess.ID, sess.UserID, sess.TokenHash, sess.CSRFHash, sess.UserAgent, sess.IP,
		fmtTime(sess.CreatedAt), fmtTime(sess.LastSeenAt), fmtTime(sess.ExpiresAt))
	return mapWriteError(err)
}

// AuthSessionByTokenHash loads a live session by the hash of its cookie value.
//
// Revoked and expired sessions are filtered in SQL rather than in Go, so a
// mistake yields "not found" instead of a usable session.
func (s *Store) AuthSessionByTokenHash(ctx context.Context, tokenHash []byte) (*AuthSession, error) {
	row := s.read.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, csrf_hash, user_agent, ip,
		       created_at, last_seen_at, expires_at, revoked_at
		FROM auth_sessions
		WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?`,
		tokenHash, fmtTime(s.now()))

	var (
		sess      AuthSession
		createdAt string
		lastSeen  string
		expiresAt string
		revokedAt sql.NullString
	)
	err := row.Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.CSRFHash,
		&sess.UserAgent, &sess.IP, &createdAt, &lastSeen, &expiresAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.CreatedAt = parseTime(createdAt)
	sess.LastSeenAt = parseTime(lastSeen)
	sess.ExpiresAt = parseTime(expiresAt)
	sess.RevokedAt = timePtr(revokedAt)
	return &sess, nil
}

// TouchAuthSession extends a session's sliding expiry.
func (s *Store) TouchAuthSession(ctx context.Context, id string, expiresAt time.Time) error {
	_, err := s.write.ExecContext(ctx,
		`UPDATE auth_sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?`,
		fmtTime(s.now()), fmtTime(expiresAt), id)
	return err
}

// RevokeAuthSession invalidates one session.
func (s *Store) RevokeAuthSession(ctx context.Context, id string) error {
	res, err := s.write.ExecContext(ctx,
		`UPDATE auth_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		fmtTime(s.now()), id)
	return affected(res, err)
}

// RevokeUserSessions invalidates every session for a user except optionally one.
// A password change calls this so a stolen session cannot outlive the reset.
func (s *Store) RevokeUserSessions(ctx context.Context, userID, exceptID string) (int, error) {
	res, err := s.write.ExecContext(ctx, `
		UPDATE auth_sessions SET revoked_at = ?
		WHERE user_id = ? AND revoked_at IS NULL AND id <> ?`,
		fmtTime(s.now()), userID, exceptID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// ListAuthSessions returns a user's live sessions.
func (s *Store) ListAuthSessions(ctx context.Context, userID string) ([]*AuthSession, error) {
	rows, err := s.read.QueryContext(ctx, `
		SELECT id, user_id, token_hash, csrf_hash, user_agent, ip,
		       created_at, last_seen_at, expires_at, revoked_at
		FROM auth_sessions
		WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
		ORDER BY last_seen_at DESC`, userID, fmtTime(s.now()))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []*AuthSession
	for rows.Next() {
		var (
			sess      AuthSession
			createdAt string
			lastSeen  string
			expiresAt string
			revokedAt sql.NullString
		)
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.CSRFHash,
			&sess.UserAgent, &sess.IP, &createdAt, &lastSeen, &expiresAt, &revokedAt); err != nil {
			return nil, err
		}
		sess.CreatedAt = parseTime(createdAt)
		sess.LastSeenAt = parseTime(lastSeen)
		sess.ExpiresAt = parseTime(expiresAt)
		sess.RevokedAt = timePtr(revokedAt)
		out = append(out, &sess)
	}
	return out, rows.Err()
}

// PurgeExpiredAuthSessions deletes sessions that expired before cutoff.
func (s *Store) PurgeExpiredAuthSessions(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.write.ExecContext(ctx,
		`DELETE FROM auth_sessions WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)`,
		fmtTime(cutoff), fmtTime(cutoff))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// affected converts an Exec result into ErrNotFound when nothing changed, so
// callers do not have to repeat the check.
func affected(res sql.Result, err error) error {
	if err != nil {
		return mapWriteError(err)
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

// joinPlaceholders builds "?, ?, ?" for an IN clause of n values.
func joinPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}
