// Package migrations applies the embedded schema.
//
// Forward-only, checksummed, one transaction per migration. A checksum mismatch
// on an already-applied migration aborts startup rather than running a schema
// different from the one recorded -- that mismatch is exactly how a routine
// upgrade becomes data loss.
//
// There are no down-migrations. For a single-file database a verified copy is
// more trustworthy than a reverse script that is rarely tested, so rollback is
// restore-from-backup and the upgrade guide makes taking that copy step one.
package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed *.sql
var files embed.FS

// Migration is one numbered schema change.
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

// AppliedMigration records a migration that has run.
type AppliedMigration struct {
	Version   int
	Name      string
	Checksum  string
	AppliedAt time.Time
}

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    checksum   TEXT NOT NULL,
    applied_at TEXT NOT NULL
)`

// Load reads and parses the embedded migrations in version order.
func Load() ([]Migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	out := make([]Migration, 0, len(entries))
	seen := make(map[int]string, len(entries))

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version, name, err := parseName(e.Name())
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("duplicate migration version %d: %s and %s", version, prev, e.Name())
		}
		seen[version] = e.Name()

		body, err := files.ReadFile(e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		sum := sha256.Sum256(body)
		out = append(out, Migration{
			Version:  version,
			Name:     name,
			SQL:      string(body),
			Checksum: hex.EncodeToString(sum[:]),
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	if len(out) == 0 {
		return nil, errors.New("no migrations were embedded")
	}
	return out, nil
}

// parseName splits "0003_inventory.sql" into 3 and "inventory".
func parseName(filename string) (int, string, error) {
	base := strings.TrimSuffix(filename, ".sql")
	idx := strings.Index(base, "_")
	if idx <= 0 {
		return 0, "", fmt.Errorf("migration %q must be named NNNN_description.sql", filename)
	}
	version, err := strconv.Atoi(base[:idx])
	if err != nil {
		return 0, "", fmt.Errorf("migration %q has a non-numeric version prefix", filename)
	}
	if version <= 0 {
		return 0, "", fmt.Errorf("migration %q must have a version of 1 or greater", filename)
	}
	return version, base[idx+1:], nil
}

// Applied lists the migrations recorded in the database.
func Applied(ctx context.Context, db *sql.DB) ([]AppliedMigration, error) {
	if _, err := db.ExecContext(ctx, createMigrationsTable); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}
	rows, err := db.QueryContext(ctx,
		`SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []AppliedMigration
	for rows.Next() {
		var (
			m  AppliedMigration
			ts string
		)
		if err := rows.Scan(&m.Version, &m.Name, &m.Checksum, &ts); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		m.AppliedAt, _ = time.Parse(time.RFC3339, ts)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema_migrations: %w", err)
	}
	return out, nil
}

// Apply brings the database up to date and returns how many migrations ran.
func Apply(ctx context.Context, db *sql.DB, log *slog.Logger) (int, error) {
	pending, err := Load()
	if err != nil {
		return 0, err
	}

	applied, err := Applied(ctx, db)
	if err != nil {
		return 0, err
	}
	appliedByVersion := make(map[int]AppliedMigration, len(applied))
	for _, a := range applied {
		appliedByVersion[a.Version] = a
	}

	// A migration that vanished from the binary means the running code is older
	// than the database. Continuing would apply an unknown schema on top.
	embedded := make(map[int]bool, len(pending))
	for _, m := range pending {
		embedded[m.Version] = true
	}
	for _, a := range applied {
		if !embedded[a.Version] {
			return 0, fmt.Errorf(
				"database has migration %d (%s) applied but this build does not contain it; "+
					"the binary is older than the database -- upgrade the binary or restore a matching backup",
				a.Version, a.Name)
		}
	}

	ran := 0
	for _, m := range pending {
		if prior, ok := appliedByVersion[m.Version]; ok {
			if prior.Checksum != m.Checksum {
				return ran, fmt.Errorf(
					"migration %d (%s) has changed since it was applied "+
						"(recorded %s, embedded %s); refusing to start, because the live schema is "+
						"not the one this build expects. Restore a backup or add a new migration instead of editing %04d",
					m.Version, m.Name, short(prior.Checksum), short(m.Checksum), m.Version)
			}
			continue
		}

		if err := applyOne(ctx, db, m); err != nil {
			return ran, err
		}
		ran++
		if log != nil {
			log.Info("migration applied",
				slog.Int("version", m.Version),
				slog.String("name", m.Name),
			)
		}
	}
	return ran, nil
}

func applyOne(ctx context.Context, db *sql.DB, m Migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migration %d (%s): begin: %w", m.Version, m.Name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("migration %d (%s): %w", m.Version, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
		m.Version, m.Name, m.Checksum, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("migration %d (%s): record: %w", m.Version, m.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %d (%s): commit: %w", m.Version, m.Name, err)
	}
	return nil
}

// Pending reports which migrations would run, without applying them.
func Pending(ctx context.Context, db *sql.DB) ([]Migration, error) {
	all, err := Load()
	if err != nil {
		return nil, err
	}
	applied, err := Applied(ctx, db)
	if err != nil {
		return nil, err
	}
	done := make(map[int]bool, len(applied))
	for _, a := range applied {
		done[a.Version] = true
	}
	var out []Migration
	for _, m := range all {
		if !done[m.Version] {
			out = append(out, m)
		}
	}
	return out, nil
}

// LatestVersion is the highest version this build contains.
func LatestVersion() (int, error) {
	all, err := Load()
	if err != nil {
		return 0, err
	}
	return all[len(all)-1].Version, nil
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}
