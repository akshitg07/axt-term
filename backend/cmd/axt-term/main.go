// Command axt-term runs the AXT-Term server.
//
// The entire dependency graph is wired explicitly in run(). There is no
// dependency-injection container: for an application this size the wiring is
// short enough to read, and reading it is how a newcomer learns the system.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/axt-term/axt-term/backend/internal/api"
	"github.com/axt-term/axt-term/backend/internal/auth"
	"github.com/axt-term/axt-term/backend/internal/buildinfo"
	"github.com/axt-term/axt-term/backend/internal/config"
	"github.com/axt-term/axt-term/backend/internal/credentials"
	"github.com/axt-term/axt-term/backend/internal/crypto"
	"github.com/axt-term/axt-term/backend/internal/events"
	"github.com/axt-term/axt-term/backend/internal/httpx"
	"github.com/axt-term/axt-term/backend/internal/inventory"
	"github.com/axt-term/axt-term/backend/internal/logging"
	"github.com/axt-term/axt-term/backend/internal/rbac"
	"github.com/axt-term/axt-term/backend/internal/sshx"
	"github.com/axt-term/axt-term/backend/internal/store"
	"github.com/axt-term/axt-term/backend/internal/terminal"
	"github.com/axt-term/axt-term/backend/internal/web"
)

func main() {
	if err := run(); err != nil {
		// Configuration and startup failures happen before the logger exists, or
		// are the reason it does not, so they go to stderr directly.
		fmt.Fprintf(os.Stderr, "axt-term: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log, err := logging.New(logging.Options{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
		Output: os.Stderr,
	})
	if err != nil {
		return err
	}
	slog.SetDefault(log)

	build := buildinfo.Get()
	log.Info("starting axt-term",
		slog.String("version", build.Version),
		slog.String("commit", build.Commit),
		slog.String("go", build.GoVersion),
		slog.String("platform", build.Platform),
		slog.String("env", cfg.Env),
	)
	logConfig(log, cfg)
	for _, concern := range cfg.Warnings() {
		log.Warn("configuration concern", slog.String("detail", concern))
	}
	if err := ensureDirectories(cfg); err != nil {
		return err
	}

	// The root context is cancelled on SIGINT or SIGTERM and drives every
	// background goroutine.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- persistence -----------------------------------------------------
	st, err := store.Open(ctx, store.OpenOptions{Path: cfg.Paths.DBPath, Log: log})
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	applied, err := st.Migrate(ctx)
	if err != nil {
		return err
	}
	if applied > 0 {
		log.Info("database migrated", slog.Int("migrations_applied", applied))
	}

	// A crash leaves session rows marked connected and transfers marked active
	// with nothing behind them. Sweeping at startup keeps history honest and lets
	// the UI offer Retry instead of showing a progress bar that will never move.
	if n, err := st.SweepOpenSessions(ctx, "server restarted"); err != nil {
		log.Warn("could not sweep open sessions", slog.Any("error", err))
	} else if n > 0 {
		log.Info("closed session records left open by a restart", slog.Int("count", n))
	}
	if n, err := st.SweepActiveTransfers(ctx, "interrupted by a server restart"); err != nil {
		log.Warn("could not sweep active transfers", slog.Any("error", err))
	} else if n > 0 {
		log.Info("marked in-flight transfers retryable", slog.Int("count", n))
	}
	if n, err := st.SweepRunningExecJobs(ctx, "interrupted by a server restart"); err != nil {
		log.Warn("could not sweep running jobs", slog.Any("error", err))
	} else if n > 0 {
		log.Info("failed command jobs left running by a restart", slog.Int("count", n))
	}

	// --- credential encryption -------------------------------------------
	keyring, err := openKeyring(ctx, st, cfg, log)
	if err != nil {
		return err
	}

	credentialSvc := credentials.NewService(st, keyring, log)
	// Refuse to serve if the configured key cannot decrypt this database.
	// Starting anyway would show an empty credential store while the real data is
	// still encrypted, and invite an operator to overwrite it.
	if err := credentialSvc.VerifyCanary(ctx); err != nil {
		return err
	}
	log.Info("credential encryption ready",
		slog.Int("key_version", int(keyring.CurrentVersion())))

	// --- permission registry ---------------------------------------------
	if err := verifyPermissions(ctx, st); err != nil {
		return err
	}

	// --- services ---------------------------------------------------------
	bus := events.NewBus(log)
	defer bus.Close()

	authSvc := auth.NewService(st, auth.Config{
		IdleTimeout:      cfg.Security.SessionIdleTimeout,
		MaxLifetime:      cfg.Security.SessionMaxLifetime,
		CookieSecure:     cfg.Security.CookieSecure,
		Argon2:           auth.DefaultArgon2,
		TicketTTL:        auth.DefaultTicketTTL,
		LoginPerIP:       cfg.RateLimit.LoginPerIP,
		LoginPerUser:     cfg.RateLimit.LoginPerUser,
		LoginWindow:      cfg.RateLimit.LoginWindow,
		LockoutThreshold: cfg.RateLimit.LockoutThreshold,
		LockoutDuration:  cfg.RateLimit.LockoutDuration,
		AllowedOrigins:   cfg.HTTP.AllowedOrigins,
	}, log, nil)

	inventorySvc := inventory.NewService(st, credentialSvc, bus, inventory.Config{
		AgentSocket: cfg.SSH.AgentSocket,
		MaxHops:     cfg.SSH.MaxHops,
	}, log)

	verifier := sshx.NewVerifier(st, cfg.SSH.HostKeyPolicy)
	dialer := sshx.NewDialer(sshx.DialConfig{
		ConnectTimeout:    cfg.SSH.ConnectTimeout,
		KeepaliveInterval: cfg.SSH.KeepaliveInterval,
		HostKeyPolicy:     cfg.SSH.HostKeyPolicy,
		LegacyAlgorithms:  cfg.SSH.LegacyAlgorithms,
		MaxHops:           cfg.SSH.MaxHops,
		ClientVersion:     "SSH-2.0-AXT-Term_" + build.Version,
	}, verifier, log)

	pool := sshx.NewPool(sshx.PoolConfig{
		IdleTimeout: 5 * time.Minute,
	}, dialer, inventorySvc.ResolveChain, log)

	sessions := terminal.NewRegistry(terminal.Config{
		RingBufferSize: cfg.Session.RingBufferSize,
		MaxPerUser:     cfg.Session.MaxPerUser,
		IdleClose:      cfg.Session.IdleClose,
		RecordingsDir:  cfg.Paths.RecordingsDir,
		CommandLogging: cfg.Session.CommandLogging,
	}, pool, st, bus, log)

	bridge := terminal.NewBridge(sessions, authSvc.Tickets(), bus, cfg.HTTP.AllowedOrigins, log)

	apiSrv := api.New(api.Deps{
		Config:    cfg,
		Store:     st,
		Auth:      authSvc,
		Creds:     credentialSvc,
		Inventory: inventorySvc,
		Sessions:  sessions,
		Bridge:    bridge,
		Pool:      pool,
		Bus:       bus,
		Log:       log,
	})

	// --- readiness --------------------------------------------------------
	health := apiSrv.HealthHandler()
	health.AddCheck(api.Check{
		Name:     "database",
		Critical: true,
		Probe:    st.Ping,
	})
	health.AddCheck(api.Check{
		Name:     "migrations",
		Critical: true,
		Probe: func(ctx context.Context) error {
			pending, err := migrationsPending(ctx, st)
			if err != nil {
				return err
			}
			if pending > 0 {
				return fmt.Errorf("%d migrations are pending", pending)
			}
			return nil
		},
	})
	if cfg.RDP.Enabled() {
		// Non-critical: a missing guacd means RDP is unavailable, not that the
		// whole workstation should be pulled out of service.
		health.AddCheck(api.Check{
			Name:  "guacd",
			Probe: func(ctx context.Context) error { return probeTCP(ctx, cfg.RDP.GuacdAddr) },
		})
	}

	// --- HTTP -------------------------------------------------------------
	handler, err := buildHandler(cfg, apiSrv, authSvc, log)
	if err != nil {
		return err
	}

	srv := httpx.NewServer(httpx.ServerConfig{
		Addr:          cfg.HTTP.Addr,
		ShutdownGrace: cfg.HTTP.ShutdownGrace,
	}, handler, log)

	// Shutdown order matches docs/architecture/03-system-architecture.md: tell
	// clients why first, then drain, then close transports, then the database.
	srv.OnDraining("notify-clients", func(context.Context) error {
		sessions.NotifyShutdown("the server is restarting")
		// A brief pause so the notification reaches browsers before their sockets
		// go away, which is what lets the UI say "restarting" instead of
		// "connection lost".
		time.Sleep(250 * time.Millisecond)
		return nil
	})
	srv.OnShutdown("close-sessions", func(context.Context) error {
		if n := sessions.CloseAll("the server is shutting down"); n > 0 {
			log.Info("closed live sessions", slog.Int("count", n))
		}
		return nil
	})
	srv.OnShutdown("close-ssh-transports", func(context.Context) error {
		pool.CloseAll()
		return nil
	})
	srv.OnShutdown("mark-transfers-interrupted", func(ctx context.Context) error {
		_, err := st.SweepActiveTransfers(ctx, "interrupted by a server shutdown")
		return err
	})
	srv.OnShutdown("checkpoint-database", st.Checkpoint)

	// --- background work --------------------------------------------------
	go pool.StartSweeper(ctx, time.Minute)
	go sessions.StartSweeper(ctx, time.Minute)
	go inventory.NewHealthChecker(inventorySvc, st, bus, log).Run(ctx)
	go runPeriodically(ctx, 10*time.Minute, func() { authSvc.Sweep(ctx) })

	log.Info("axt-term ready",
		slog.String("url", cfg.HTTP.PublicURL.String()),
		slog.Bool("rdp", cfg.RDP.Enabled()),
		slog.String("hostkey_policy", cfg.SSH.HostKeyPolicy))

	return srv.Run(ctx)
}

// buildHandler assembles the global middleware chain and the route table.
//
// Order matters and is deliberate:
//
//	AssignRequestID    every later layer logs and reports the same id
//	RealIP             rate limiting and audit need the true client address
//	SecurityHeaders    set before any handler can write a body
//	AccessLog          wraps the writer, so it sits outside Recover to observe
//	                   the 500 that Recover writes
//	Recover            innermost of the infrastructure layers
//	RequireOrigin      reject cross-site before touching a session
//	Authenticate       resolve the cookie into a Principal
//	RequireCSRF        double-submit check on state-changing requests
//	RateLimit          per-user throttling, after identity is known
//	RequirePasswordChange
//	Authorize          per-route permission check
func buildHandler(cfg *config.Config, apiSrv *api.Server, authSvc *auth.Service, log *slog.Logger) (http.Handler, error) {
	router := httpx.NewRouter(
		httpx.AssignRequestID,
		httpx.RealIP(cfg.HTTP.TrustedProxies),
		httpx.SecurityHeaders(httpx.SecurityHeaderOptions{TLS: cfg.Security.CookieSecure}),
		httpx.AccessLog(log),
		httpx.Recover(log),
		auth.RequireOrigin(cfg.HTTP.AllowedOrigins, log),
		authSvc.Authenticate,
		authSvc.RequireCSRF,
		authSvc.RateLimit(cfg.RateLimit.GeneralPerMinute, cfg.RateLimit.GeneralBurst),
		auth.RequirePasswordChange,
	)

	apiSrv.Register(router)

	// Authorisation is applied per route from the declarations in the table, so a
	// route cannot be served without its check having run.
	router.Authorize = auth.Authorize

	// Startup fails if any route omitted its protection or names a permission the
	// registry does not know. An unprotected endpoint therefore becomes a
	// deployment failure rather than a vulnerability discovered later.
	if err := router.Validate(rbac.Exists); err != nil {
		return nil, err
	}

	static, err := web.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.NotFound(w, r, "endpoint")
	}))
	if err != nil {
		return nil, err
	}
	router.NotFound = static

	log.Info("routes registered", slog.Int("count", len(router.Routes())))
	if !static.Built() {
		log.Warn("no frontend build is embedded in this binary",
			slog.String("effect", "the API works but the web UI is a placeholder"),
			slog.String("fix", "run `make web-build && make build`"))
	}
	for _, route := range router.Routes() {
		log.Debug("route",
			slog.String("method", route.Method),
			slog.String("pattern", route.Pattern),
			slog.String("access", route.Access.String()),
			slog.String("permission", route.Permission))
	}
	return router.Handler(), nil
}

// openKeyring loads the master key, creating the key record on first run.
func openKeyring(ctx context.Context, st *store.Store, cfg *config.Config, log *slog.Logger) (*crypto.Keyring, error) {
	source := crypto.KeySource{
		Base64:     cfg.Security.MasterKey,
		File:       cfg.Security.MasterKeyFile,
		Passphrase: cfg.Security.MasterPassphrase,
	}
	if source.IsZero() {
		return nil, errors.New(
			"no master key configured: set AXT_MASTER_KEY_FILE (preferred), AXT_MASTER_KEY, or " +
				"AXT_MASTER_PASSPHRASE. Generate one with: openssl rand -base64 32")
	}

	record, err := st.CurrentCryptoKey(ctx)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		record, err = createFirstKeyRecord(ctx, st, source, log)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	var kdf *crypto.KDFParams
	if record.KDF == "argon2id" {
		params := crypto.KDFParams{Salt: record.KDFSalt}
		if record.KDFParams != "" {
			if err := json.Unmarshal([]byte(record.KDFParams), &params); err != nil {
				return nil, fmt.Errorf("stored KDF parameters are unreadable: %w", err)
			}
			params.Salt = record.KDFSalt
		}
		kdf = &params
	}
	if cfg.Security.MasterPassphrase != "" && kdf == nil {
		return nil, errors.New(
			"AXT_MASTER_PASSPHRASE is set but this database was initialised with a raw key; " +
				"supply the original AXT_MASTER_KEY or AXT_MASTER_KEY_FILE instead")
	}

	key, err := crypto.LoadMasterKey(source, kdf)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(key)

	return crypto.NewKeyring(uint16(record.Version), key)
}

func createFirstKeyRecord(ctx context.Context, st *store.Store, source crypto.KeySource, log *slog.Logger) (*store.CryptoKey, error) {
	version, err := st.NextCryptoKeyVersion(ctx)
	if err != nil {
		return nil, err
	}
	record := &store.CryptoKey{Version: version, Algo: "aes-256-gcm"}

	// A passphrase needs its salt and cost persisted, or the same passphrase would
	// derive a different key after a restart and orphan every stored credential.
	if source.Passphrase != "" {
		params, err := crypto.DefaultKDFParams()
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		record.KDF = "argon2id"
		record.KDFSalt = params.Salt
		record.KDFParams = string(encoded)
	}

	if err := st.CreateCryptoKey(ctx, record); err != nil {
		return nil, err
	}
	log.Info("initialised credential encryption",
		slog.Int("key_version", version),
		slog.String("kdf", record.KDF))
	return record, nil
}

// verifyPermissions confirms the code's registry and the seeded rows agree.
//
// Drift in either direction is a bug: a key in the database that code does not
// know can never be referenced by a route, and a key in code that was never
// seeded can never be granted to a role.
func verifyPermissions(ctx context.Context, st *store.Store) error {
	seeded, err := st.ListPermissions(ctx)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(seeded))
	for _, p := range seeded {
		keys = append(keys, p.Key)
	}
	return rbac.VerifyAgainstKeys(keys)
}

func migrationsPending(ctx context.Context, st *store.Store) (int, error) {
	// Readiness only needs the count, and the store owns the migration runner.
	return st.PendingMigrationCount(ctx)
}

func probeTCP(ctx context.Context, addr string) error {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

func runPeriodically(ctx context.Context, interval time.Duration, fn func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn()
		}
	}
}

func logConfig(log *slog.Logger, cfg *config.Config) {
	fields := cfg.Redacted()
	attrs := make([]any, 0, len(fields))
	for _, f := range fields {
		attrs = append(attrs, slog.String(f.Key, f.Value))
	}
	log.Debug("effective configuration", attrs...)
}

func ensureDirectories(cfg *config.Config) error {
	// 0o750 rather than 0o755: the data directory holds the database with
	// encrypted credentials, and there is no reason for other local users to list
	// it.
	if err := os.MkdirAll(cfg.Paths.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data directory %s: %w", cfg.Paths.DataDir, err)
	}
	// Recordings can contain anything that crossed a terminal, so they are
	// owner-only.
	if err := os.MkdirAll(cfg.Paths.RecordingsDir, 0o700); err != nil {
		return fmt.Errorf("create recordings directory %s: %w", cfg.Paths.RecordingsDir, err)
	}
	return nil
}
