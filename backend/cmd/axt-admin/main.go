// Command axt-admin performs administrative tasks against an AXT-Term database.
//
// Deliberately a separate binary from the server. Bootstrapping the first
// administrator, rotating the master key, and pruning the audit log all need
// filesystem access to the database and the key, and none of them should be
// reachable over HTTP -- an attacker with the web UI must not be able to mint an
// admin account or clear the audit trail.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/axt-term/axt-term/backend/internal/auth"
	"github.com/axt-term/axt-term/backend/internal/config"
	"github.com/axt-term/axt-term/backend/internal/credentials"
	"github.com/axt-term/axt-term/backend/internal/crypto"
	"github.com/axt-term/axt-term/backend/internal/logging"
	"github.com/axt-term/axt-term/backend/internal/store"
	"github.com/google/uuid"
)

const usage = `axt-admin -- AXT-Term administration

Usage:
  axt-admin <command> [flags]

Commands:
  user create        Create a user account
  user list          List accounts and their roles
  user passwd        Set a user's password
  user disable       Deactivate an account without deleting it
  user enable        Reactivate an account
  key generate       Print a new base64 master key
  key rotate         Re-wrap every credential under a new master key
  backup             Write a consistent copy of the database
  migrate            Apply pending migrations and exit
  audit prune        Delete audit entries older than a cutoff
  status             Show database and encryption status

Configuration comes from the same environment variables as the server; see
docs/configuration.md. Run a command with -h for its flags.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "axt-admin: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return nil
	}

	command := args[0]
	rest := args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		command = command + " " + rest[0]
		rest = rest[1:]
	}

	switch command {
	case "user create":
		return userCreate(rest)
	case "user list":
		return userList(rest)
	case "user passwd":
		return userPasswd(rest)
	case "user disable":
		return userSetActive(rest, false)
	case "user enable":
		return userSetActive(rest, true)
	case "key generate":
		return keyGenerate()
	case "key rotate":
		return keyRotate(rest)
	case "backup":
		return backup(rest)
	case "migrate":
		return migrate()
	case "audit prune":
		return auditPrune(rest)
	case "status":
		return status()
	default:
		fmt.Print(usage)
		return fmt.Errorf("unknown command %q", command)
	}
}

// env loads configuration and opens the database.
func env(ctx context.Context) (*config.Config, *store.Store, *slog.Logger, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, nil, err
	}
	log, err := logging.New(logging.Options{Level: "warn", Format: "text", Output: os.Stderr})
	if err != nil {
		return nil, nil, nil, err
	}
	st, err := store.Open(ctx, store.OpenOptions{Path: cfg.Paths.DBPath, Log: log})
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := st.Migrate(ctx); err != nil {
		_ = st.Close()
		return nil, nil, nil, err
	}
	return cfg, st, log, nil
}

// keyringFor loads the master key the same way the server does, so a mismatch is
// reported here rather than at the next server start.
func keyringFor(ctx context.Context, cfg *config.Config, st *store.Store) (*crypto.Keyring, error) {
	record, err := st.CurrentCryptoKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("no encryption key record found; start the server once to initialise it: %w", err)
	}

	var kdf *crypto.KDFParams
	if record.KDF == "argon2id" {
		params := crypto.KDFParams{Salt: record.KDFSalt}
		if record.KDFParams != "" {
			if err := json.Unmarshal([]byte(record.KDFParams), &params); err != nil {
				return nil, err
			}
			params.Salt = record.KDFSalt
		}
		kdf = &params
	}

	key, err := crypto.LoadMasterKey(crypto.KeySource{
		Base64:     cfg.Security.MasterKey,
		File:       cfg.Security.MasterKeyFile,
		Passphrase: cfg.Security.MasterPassphrase,
	}, kdf)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(key)
	return crypto.NewKeyring(uint16(record.Version), key)
}

func authService(cfg *config.Config, st *store.Store, log *slog.Logger) *auth.Service {
	return auth.NewService(st, auth.Config{
		IdleTimeout:  cfg.Security.SessionIdleTimeout,
		MaxLifetime:  cfg.Security.SessionMaxLifetime,
		CookieSecure: cfg.Security.CookieSecure,
		Argon2:       auth.DefaultArgon2,
	}, log, nil)
}

func userCreate(args []string) error {
	fs := flag.NewFlagSet("user create", flag.ContinueOnError)
	username := fs.String("username", "", "account name (required)")
	password := fs.String("password", "", "password; generated and printed if omitted")
	role := fs.String("role", "admin", "role to assign: admin, operator, or viewer")
	email := fs.String("email", "", "email address")
	display := fs.String("display-name", "", "display name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		fs.Usage()
		return errors.New("--username is required")
	}

	ctx := context.Background()
	cfg, st, log, err := env(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	generated := ""
	pw := *password
	if pw == "" {
		pw, err = auth.GeneratePassword(24)
		if err != nil {
			return err
		}
		generated = pw
	}
	if err := auth.ValidatePassword(pw); err != nil {
		return err
	}

	hash, err := auth.HashPassword(pw, auth.DefaultArgon2)
	if err != nil {
		return err
	}
	name := *display
	if name == "" {
		name = *username
	}

	user := &store.User{
		ID:          uuid.NewString(),
		Username:    *username,
		Email:       *email,
		DisplayName: name,
		PasswordHash: hash,
		IsActive:    true,
		// A generated password must be changed on first use; an operator-supplied
		// one is assumed deliberate.
		MustChangePassword: generated != "",
	}
	if err := st.CreateUser(ctx, user, []string{*role}); err != nil {
		return err
	}

	fmt.Printf("created user %q with role %q\n", user.Username, *role)
	if generated != "" {
		// Printed exactly once, and only to stdout, so it can be piped to a
		// password manager rather than left in a shell history file.
		fmt.Printf("\n  password: %s\n\n", generated)
		fmt.Println("This password is shown once and must be changed at first login.")
	}
	_ = cfg
	_ = log
	return nil
}

func userList(args []string) error {
	fs := flag.NewFlagSet("user list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()
	_, st, _, err := env(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	users, err := st.ListUsers(ctx)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Println("no users exist; create one with: axt-admin user create --username admin")
		return nil
	}

	fmt.Printf("%-24s %-10s %-24s %-20s %s\n", "USERNAME", "STATE", "ROLES", "LAST LOGIN", "MUST CHANGE PW")
	for _, u := range users {
		state := "active"
		if !u.IsActive {
			state = "disabled"
		}
		if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
			state = "locked"
		}
		last := "never"
		if u.LastLoginAt != nil {
			last = u.LastLoginAt.Format("2006-01-02 15:04")
		}
		fmt.Printf("%-24s %-10s %-24s %-20s %v\n",
			u.Username, state, strings.Join(u.Roles, ","), last, u.MustChangePassword)
	}
	return nil
}

func userPasswd(args []string) error {
	fs := flag.NewFlagSet("user passwd", flag.ContinueOnError)
	username := fs.String("username", "", "account name (required)")
	password := fs.String("password", "", "new password; generated and printed if omitted")
	noChange := fs.Bool("no-force-change", false, "do not require a change at next login")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return errors.New("--username is required")
	}

	ctx := context.Background()
	cfg, st, log, err := env(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	user, err := st.UserByUsername(ctx, *username)
	if err != nil {
		return err
	}

	generated := ""
	pw := *password
	if pw == "" {
		pw, err = auth.GeneratePassword(24)
		if err != nil {
			return err
		}
		generated = pw
	}

	if err := authService(cfg, st, log).SetPasswordAsAdmin(ctx, user.ID, pw, !*noChange); err != nil {
		return err
	}

	fmt.Printf("password updated for %q; all other sessions revoked\n", user.Username)
	if generated != "" {
		fmt.Printf("\n  password: %s\n\n", generated)
	}
	return nil
}

func userSetActive(args []string, active bool) error {
	fs := flag.NewFlagSet("user state", flag.ContinueOnError)
	username := fs.String("username", "", "account name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return errors.New("--username is required")
	}

	ctx := context.Background()
	_, st, _, err := env(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	user, err := st.UserByUsername(ctx, *username)
	if err != nil {
		return err
	}
	if err := st.UpdateUserProfile(ctx, user.ID, user.Email, user.DisplayName, active); err != nil {
		return err
	}
	if !active {
		// Deactivation must take effect immediately, not at the next session
		// expiry.
		if n, err := st.RevokeUserSessions(ctx, user.ID, ""); err == nil && n > 0 {
			fmt.Printf("revoked %d active session(s)\n", n)
		}
	}
	fmt.Printf("user %q is now %s\n", user.Username, map[bool]string{true: "active", false: "disabled"}[active])
	return nil
}

func keyGenerate() error {
	key, err := crypto.GenerateMasterKey()
	if err != nil {
		return err
	}
	fmt.Println(key)
	fmt.Fprintln(os.Stderr, "\nStore this outside the database. Losing it loses every stored credential.")
	return nil
}

func keyRotate(args []string) error {
	fs := flag.NewFlagSet("key rotate", flag.ContinueOnError)
	newKeyFile := fs.String("new-key-file", "", "file containing the new base64 master key (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *newKeyFile == "" {
		return errors.New("--new-key-file is required; generate one with: axt-admin key generate > newkey")
	}

	ctx := context.Background()
	cfg, st, log, err := env(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	// The current key must still load, because every wrapped data key has to be
	// opened before it can be re-wrapped.
	keyring, err := keyringFor(ctx, cfg, st)
	if err != nil {
		return fmt.Errorf("the current master key must be configured to rotate: %w", err)
	}
	oldVersion := keyring.CurrentVersion()

	newKey, err := crypto.LoadMasterKey(crypto.KeySource{File: *newKeyFile}, nil)
	if err != nil {
		return err
	}
	defer crypto.Zero(newKey)

	nextVersion, err := st.NextCryptoKeyVersion(ctx)
	if err != nil {
		return err
	}
	if err := keyring.AddVersion(uint16(nextVersion), newKey); err != nil {
		return err
	}
	if err := keyring.SetCurrent(uint16(nextVersion)); err != nil {
		return err
	}
	if err := st.CreateCryptoKey(ctx, &store.CryptoKey{Version: nextVersion, Algo: "aes-256-gcm"}); err != nil {
		return err
	}

	svc := credentials.NewService(st, keyring, log)
	count, err := svc.RotateMasterKey(ctx)
	if err != nil {
		return fmt.Errorf("rotation stopped after %d credential(s): %w -- the old key is still valid, so re-run once the cause is fixed", count, err)
	}
	if err := st.RetireCryptoKey(ctx, int(oldVersion)); err != nil {
		return err
	}

	fmt.Printf("re-wrapped %d credential(s) from key version %d to %d\n", count, oldVersion, nextVersion)
	fmt.Println("Update AXT_MASTER_KEY_FILE to the new key and restart the server.")
	fmt.Println("Keep the old key until you have confirmed the new one works.")
	return nil
}

func backup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("out", "", "destination file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required")
	}

	ctx := context.Background()
	_, st, _, err := env(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	if err := st.Backup(ctx, *out); err != nil {
		return err
	}
	info, err := os.Stat(*out)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s (%.1f MiB)\n", *out, float64(info.Size())/(1024*1024))
	fmt.Println("\nThis file contains encrypted credentials. Back up the master key SEPARATELY:")
	fmt.Println("a backup holding both is a backup of your plaintext secrets.")
	return nil
}

func migrate() error {
	ctx := context.Background()
	_, st, _, err := env(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	pending, err := st.PendingMigrationCount(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("schema is up to date (%d pending)\n", pending)
	return nil
}

func auditPrune(args []string) error {
	fs := flag.NewFlagSet("audit prune", flag.ContinueOnError)
	before := fs.String("before", "", "delete entries older than this RFC 3339 date (required)")
	confirm := fs.Bool("confirm", false, "actually delete; without this the count is only reported")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *before == "" {
		return errors.New("--before is required, for example --before 2025-01-01T00:00:00Z")
	}
	cutoff, err := time.Parse(time.RFC3339, *before)
	if err != nil {
		cutoff, err = time.Parse("2006-01-02", *before)
		if err != nil {
			return fmt.Errorf("--before must be an RFC 3339 timestamp or YYYY-MM-DD")
		}
	}

	ctx := context.Background()
	_, st, _, err := env(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	total, err := st.CountAudit(ctx)
	if err != nil {
		return err
	}
	if !*confirm {
		// Pruning an audit log is irreversible and is itself something an
		// investigator would want to know about, so it never happens implicitly.
		fmt.Printf("%d audit entries exist in total. Re-run with --confirm to delete those before %s.\n",
			total, cutoff.Format(time.RFC3339))
		return nil
	}

	deleted, err := st.PruneAudit(ctx, cutoff)
	if err != nil {
		return err
	}
	// The prune is itself audited, so the gap in the log has an explanation.
	if err := st.RecordAudit(ctx, &store.AuditEvent{
		Action:   "audit.prune",
		Username: "axt-admin",
		Target:   cutoff.Format(time.RFC3339),
		Result:   store.AuditSuccess,
		Severity: store.SeverityWarning,
		Detail:   map[string]any{"deleted": deleted, "cutoff": cutoff.Format(time.RFC3339)},
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not record the prune itself: %v\n", err)
	}
	fmt.Printf("deleted %d audit entries older than %s\n", deleted, cutoff.Format(time.RFC3339))
	return nil
}

func status() error {
	ctx := context.Background()
	cfg, st, log, err := env(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	users, _ := st.CountUsers(ctx)
	hosts, _ := st.ListHosts(ctx, store.HostFilter{})
	creds, _ := st.ListCredentials(ctx)
	auditCount, _ := st.CountAudit(ctx)
	pending, _ := st.PendingMigrationCount(ctx)

	fmt.Printf("database        %s\n", cfg.Paths.DBPath)
	fmt.Printf("users           %d\n", users)
	fmt.Printf("hosts           %d\n", len(hosts))
	fmt.Printf("credentials     %d\n", len(creds))
	fmt.Printf("audit entries   %d\n", auditCount)
	fmt.Printf("pending migr.   %d\n", pending)

	if keyring, err := keyringFor(ctx, cfg, st); err != nil {
		fmt.Printf("encryption      UNAVAILABLE: %v\n", err)
	} else {
		fmt.Printf("encryption      key version %d\n", keyring.CurrentVersion())
		svc := credentials.NewService(st, keyring, log)
		if err := svc.VerifyCanary(ctx); err != nil {
			fmt.Printf("canary          FAILED: %v\n", err)
		} else {
			fmt.Printf("canary          ok\n")
		}
	}
	return nil
}
