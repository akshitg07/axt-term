package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/axt-term/axt-term/backend/internal/migrations"

	_ "modernc.org/sqlite" // pure-Go driver: no CGO, so the binary stays static
)

// Sentinel errors services map onto HTTP statuses.
var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
	// ErrInUse means a row is referenced by another and cannot be deleted
	// without force.
	ErrInUse = errors.New("store: referenced by other records")
)

// readPoolSize bounds concurrent readers. SQLite reads are in-process and
// microsecond-scale, so a small pool is plenty and keeps file descriptor use low.
const readPoolSize = 8

// Store is the SQLite-backed persistence layer.
//
// Two connection pools, deliberately:
//
//	write: MaxOpenConns(1). SQLite permits one writer at a time. Serialising in
//	       the pool removes SQLITE_BUSY as a failure mode instead of retrying
//	       around it, which is both simpler and more predictable under load.
//	read:  a small pool. WAL allows readers to proceed concurrently with the
//	       writer, so reads never block behind an insert.
type Store struct {
	write *sql.DB
	read  *sql.DB
	path  string
	log   *slog.Logger

	// now is injectable so tests can control time without sleeping.
	now func() time.Time
}

// OpenOptions configures Open.
type OpenOptions struct {
	Path string
	Log  *slog.Logger
	// Now overrides the clock. Tests set this; production leaves it nil.
	Now func() time.Time
}

// Open connects to the database, applying the pragmas AXT-Term relies on.
func Open(ctx context.Context, opts OpenOptions) (*Store, error) {
	if opts.Path == "" {
		return nil, errors.New("store: database path is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}

	if dir := filepath.Dir(opts.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("store: create database directory: %w", err)
		}
	}

	write, err := openPool(opts.Path, 1)
	if err != nil {
		return nil, err
	}
	read, err := openPool(opts.Path, readPoolSize)
	if err != nil {
		_ = write.Close()
		return nil, err
	}

	s := &Store{write: write, read: read, path: opts.Path, log: opts.Log, now: opts.Now}

	if err := s.write.PingContext(ctx); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("store: open %s: %w", opts.Path, err)
	}
	if err := s.verifyPragmas(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func openPool(path string, maxOpen int) (*sql.DB, error) {
	// modernc.org/sqlite reads _pragma parameters from the DSN and applies them
	// to every connection in the pool, which matters because a pragma set on one
	// connection does not affect the others.
	//
	// The path is not URL-escaped: slashes must survive, and percent-encoding a
	// filesystem path here turns /var/lib/axt.db into a filename containing
	// literal %2F.
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxOpen)
	// SQLite connections are cheap and local; keeping them alive avoids
	// re-applying pragmas constantly.
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(5 * time.Minute)
	return db, nil
}

// verifyPragmas confirms the settings correctness depends on actually took
// effect. Foreign keys silently defaulting to off would let orphaned rows
// accumulate unnoticed, which is precisely the class of corruption that is
// painful to discover months later.
func (s *Store) verifyPragmas(ctx context.Context) error {
	var foreignKeys int
	if err := s.write.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return fmt.Errorf("store: read foreign_keys pragma: %w", err)
	}
	if foreignKeys != 1 {
		return errors.New("store: foreign key enforcement is off; refusing to run with referential integrity disabled")
	}

	var journalMode string
	if err := s.write.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("store: read journal_mode pragma: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		// Not fatal: an in-memory database used by tests reports "memory".
		s.log.Warn("sqlite journal mode is not WAL",
			slog.String("mode", journalMode),
			slog.String("effect", "readers will block behind writers"))
	}
	return nil
}

// Migrate applies pending migrations and returns how many ran.
func (s *Store) Migrate(ctx context.Context) (int, error) {
	return migrations.Apply(ctx, s.write, s.log)
}

// PendingMigrationCount reports how many migrations have not been applied. Used
// by the readiness probe, so a partially-upgraded instance reports not-ready
// rather than serving against a schema it does not expect.
func (s *Store) PendingMigrationCount(ctx context.Context) (int, error) {
	pending, err := migrations.Pending(ctx, s.write)
	if err != nil {
		return 0, err
	}
	return len(pending), nil
}

// Close releases both pools.
func (s *Store) Close() error {
	var errs []error
	if s.read != nil {
		if err := s.read.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.write != nil {
		if err := s.write.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Ping checks the database is reachable. Used by the readiness probe.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.read.PingContext(ctx); err != nil {
		return err
	}
	var one int
	return s.read.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}

// Checkpoint flushes the write-ahead log into the main database file. Run at
// shutdown so a backup taken from the filesystem afterwards is complete.
func (s *Store) Checkpoint(ctx context.Context) error {
	_, err := s.write.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	if err != nil {
		return fmt.Errorf("store: wal checkpoint: %w", err)
	}
	return nil
}

// Backup writes a consistent copy to dest while the instance keeps running.
//
// VACUUM INTO produces a defragmented, transactionally consistent file without
// stopping the service, which is what makes the documented backup procedure a
// single command an operator will actually run.
func (s *Store) Backup(ctx context.Context, dest string) error {
	if dest == "" {
		return errors.New("store: backup destination is required")
	}
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("store: backup destination %s already exists", dest)
	}
	if dir := filepath.Dir(dest); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("store: create backup directory: %w", err)
		}
	}
	if _, err := s.write.ExecContext(ctx, "VACUUM INTO ?", dest); err != nil {
		return fmt.Errorf("store: backup to %s: %w", dest, err)
	}
	return nil
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// Now returns the store's clock, so callers stamp times consistently with it.
func (s *Store) Now() time.Time { return s.now() }

// Stats reports connection pool usage, for the metrics endpoint.
func (s *Store) Stats() (write, read sql.DBStats) {
	return s.write.Stats(), s.read.Stats()
}

// tx runs fn inside a write transaction, rolling back on error or panic.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	committed = true
	return nil
}

// ------------------------------------------------------- value conversions ---

// fmtTime renders a timestamp in the stored format.
func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// fmtTimePtr renders a nullable timestamp, yielding SQL NULL for nil.
func fmtTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return fmtTime(*t)
}

// parseTime reads a stored timestamp. Both RFC3339Nano (written by this
// application) and second precision (written by the SQL seed migrations) parse.
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// timePtr converts a nullable timestamp column.
func timePtr(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t := parseTime(ns.String)
	if t.IsZero() {
		return nil
	}
	return &t
}

// nullIfEmpty maps an empty string to SQL NULL, for nullable foreign keys the
// models represent as "".
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullIfZero maps 0 to SQL NULL, for nullable integer columns.
func nullIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

// str reads a nullable text column as a plain string.
func str(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return ns.String
}

// intPtr converts a nullable integer column.
func intPtr(ni sql.NullInt64) *int {
	if !ni.Valid {
		return nil
	}
	v := int(ni.Int64)
	return &v
}

// int64Ptr converts a nullable big integer column.
func int64Ptr(ni sql.NullInt64) *int64 {
	if !ni.Valid {
		return nil
	}
	v := ni.Int64
	return &v
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// isUniqueViolation recognises a duplicate-key failure without depending on the
// driver's error type, which differs between SQLite drivers.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") || strings.Contains(msg, "constraint failed: unique")
}

// isForeignKeyViolation recognises a referential integrity failure.
func isForeignKeyViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "foreign key constraint")
}

// mapWriteError converts driver errors into the package's sentinels so handlers
// can map them onto HTTP statuses without inspecting driver internals.
func mapWriteError(err error) error {
	switch {
	case err == nil:
		return nil
	case isUniqueViolation(err):
		return fmt.Errorf("%w: %v", ErrConflict, err)
	case isForeignKeyViolation(err):
		return fmt.Errorf("%w: %v", ErrInUse, err)
	default:
		return err
	}
}
