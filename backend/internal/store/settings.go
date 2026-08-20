package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Binary settings (currently only the crypto canary) are base64-encoded inside
// the JSON value, so the settings table stays uniformly textual and readable in
// a sqlite3 shell.

func encodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("store: decode binary setting: %w", err)
	}
	return b, nil
}

// Settings are stored as JSON values so a setting can change shape without a
// migration, while the Go side stays typed at the call site.

// Setting reads one global setting into dst.
func (s *Store) Setting(ctx context.Context, key string, dst any) error {
	var raw string
	err := s.read.QueryRowContext(ctx, `SELECT value_json FROM settings WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if dst == nil {
		return nil
	}
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		return fmt.Errorf("store: decode setting %s: %w", key, err)
	}
	return nil
}

// SettingBytes reads a raw setting value, used for the crypto canary blob.
func (s *Store) SettingBytes(ctx context.Context, key string) ([]byte, error) {
	var encoded string
	if err := s.Setting(ctx, key, &encoded); err != nil {
		return nil, err
	}
	return decodeBase64(encoded)
}

// SetSetting writes one global setting.
func (s *Store) SetSetting(ctx context.Context, key string, value any, updatedBy string) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("store: encode setting %s: %w", key, err)
	}
	_, err = s.write.ExecContext(ctx, `
		INSERT INTO settings (key, value_json, updated_at, updated_by)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			value_json = excluded.value_json,
			updated_at = excluded.updated_at,
			updated_by = excluded.updated_by`,
		key, string(raw), fmtTime(s.now()), nullIfEmpty(updatedBy))
	return mapWriteError(err)
}

// SetSettingBytes writes a binary setting, base64-encoded inside the JSON value.
func (s *Store) SetSettingBytes(ctx context.Context, key string, value []byte, updatedBy string) error {
	return s.SetSetting(ctx, key, encodeBase64(value), updatedBy)
}

// AllSettings returns every global setting as raw JSON, for the settings screen.
func (s *Store) AllSettings(ctx context.Context) (map[string]json.RawMessage, error) {
	rows, err := s.read.QueryContext(ctx, `SELECT key, value_json FROM settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]json.RawMessage)
	for rows.Next() {
		var key, raw string
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, err
		}
		out[key] = json.RawMessage(raw)
	}
	return out, rows.Err()
}

// DeleteSetting removes a global setting, restoring its default.
func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	_, err := s.write.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, key)
	return err
}

// UserSettings returns a user's preferences as raw JSON values.
func (s *Store) UserSettings(ctx context.Context, userID string) (map[string]json.RawMessage, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT key, value_json FROM user_settings WHERE user_id = ? ORDER BY key`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]json.RawMessage)
	for rows.Next() {
		var key, raw string
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, err
		}
		out[key] = json.RawMessage(raw)
	}
	return out, rows.Err()
}

// SetUserSettings writes several preferences at once, which is how the settings
// screen saves: one round trip, one transaction, no half-applied theme.
func (s *Store) SetUserSettings(ctx context.Context, userID string, values map[string]json.RawMessage) error {
	if len(values) == 0 {
		return nil
	}
	now := fmtTime(s.now())
	return s.tx(ctx, func(tx *sql.Tx) error {
		for key, raw := range values {
			if !json.Valid(raw) {
				return fmt.Errorf("store: user setting %s is not valid JSON", key)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO user_settings (user_id, key, value_json, updated_at)
				VALUES (?, ?, ?, ?)
				ON CONFLICT(user_id, key) DO UPDATE SET
					value_json = excluded.value_json,
					updated_at = excluded.updated_at`,
				userID, key, string(raw), now); err != nil {
				return mapWriteError(err)
			}
		}
		return nil
	})
}

// DeleteUserSetting removes one preference.
func (s *Store) DeleteUserSetting(ctx context.Context, userID, key string) error {
	_, err := s.write.ExecContext(ctx,
		`DELETE FROM user_settings WHERE user_id = ? AND key = ?`, userID, key)
	return err
}
