// Package config loads AXT-Term's configuration from the process environment.
//
// Three properties matter here and shape the design:
//
//  1. A misconfigured deployment must report every problem at once. Operators
//     should not discover configuration errors one restart at a time, so the
//     loader accumulates errors rather than returning on the first.
//
//  2. Secrets must never leak through diagnostics. Fields marked secret are
//     masked by Redacted, which is what the startup banner logs.
//
//  3. Documentation must not drift. Every variable is recorded with its
//     default and description as it is read, so docs/configuration.md is
//     generated from the same code that parses the environment.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Deployment environments.
const (
	EnvProduction  = "production"
	EnvDevelopment = "development"
)

// SSH host key policies.
const (
	HostKeyPolicyTOFU   = "tofu"   // prompt on first contact, then pin
	HostKeyPolicyStrict = "strict" // only already-trusted keys are accepted
)

// Command logging verbosity. See docs/architecture/06-security.md §6.11.
const (
	CommandLoggingOff      = "off"
	CommandLoggingCommands = "commands"
	CommandLoggingFull     = "full"
)

// Config is the fully resolved, validated configuration.
type Config struct {
	Env string

	HTTP      HTTP
	Log       Log
	Paths     Paths
	Security  Security
	SSH       SSH
	Session   Session
	Transfer  Transfer
	Files     Files
	Tunnels   Tunnels
	RDP       RDP
	Audit     Audit
	RateLimit RateLimit

	fields []FieldDoc
}

// HTTP holds listener and origin settings.
type HTTP struct {
	Addr           string
	PublicURL      *url.URL
	AllowedOrigins []string
	TrustedProxies []netip.Prefix
	RequestTimeout time.Duration
	ShutdownGrace  time.Duration
	MetricsEnabled bool
}

// Log holds logging settings.
type Log struct {
	Level  string
	Format string
}

// Paths holds resolved filesystem locations.
type Paths struct {
	DataDir       string
	DBPath        string
	RecordingsDir string
}

// Security holds authentication and credential-encryption settings.
type Security struct {
	MasterKey        string // base64, 32 bytes decoded
	MasterKeyFile    string
	MasterPassphrase string

	SessionIdleTimeout time.Duration
	SessionMaxLifetime time.Duration

	// CookieSecure is derived from PublicURL's scheme. Browsers reject
	// Secure cookies over plain HTTP, so a http:// deployment must not set
	// the attribute or every login silently fails.
	CookieSecure bool
}

// SSH holds SSH engine settings.
type SSH struct {
	HostKeyPolicy     string
	ConnectTimeout    time.Duration
	KeepaliveInterval time.Duration
	MaxHops           int
	LegacyAlgorithms  bool
	AgentSocket       string
}

// Session holds terminal-session settings.
type Session struct {
	IdleClose      time.Duration
	RingBufferSize int
	MaxPerUser     int
	CommandLogging string
}

// Transfer holds file-transfer settings.
type Transfer struct {
	Workers        int
	UploadMaxBytes int64 // 0 = unlimited
}

// Files holds remote file and editor limits.
type Files struct {
	EditorMaxBytes int64
}

// Tunnels holds port-forwarding settings.
type Tunnels struct {
	// AllowPublicBind permits tunnels to listen on addresses other than
	// loopback. Off by default: a tunnel that silently exposes an internal
	// database to the LAN is an incident, not a convenience.
	AllowPublicBind bool
}

// RDP holds the Guacamole gateway settings.
type RDP struct {
	GuacdAddr string
}

// Enabled reports whether RDP can be offered at all.
func (r RDP) Enabled() bool { return r.GuacdAddr != "" }

// Audit holds audit log settings.
type Audit struct {
	RetentionDays int // 0 = retain indefinitely; pruning is an admin action
}

// RateLimit holds request throttling settings.
type RateLimit struct {
	LoginPerIP           int
	LoginPerUser         int
	LoginWindow          time.Duration
	LockoutThreshold     int
	LockoutDuration      time.Duration
	GeneralPerMinute     int
	GeneralBurst         int
	SessionCreatePerMin  int
	TicketPerMinute      int
	DiscoveryConcurrency int
}

// FieldDoc describes one environment variable: enough to generate reference
// documentation and to print a redacted startup banner.
type FieldDoc struct {
	Key     string
	Value   string // effective value, masked when Secret
	Default string
	Doc     string
	Kind    string
	Allowed []string
	Secret  bool
}

// Load reads configuration from the process environment.
func Load() (*Config, error) { return load(osLookup) }

// Describe returns documentation for every variable, resolved against an empty
// environment so the values shown are the defaults. Used by `make docs-config`.
func Describe() []FieldDoc {
	c, _ := load(func(string) (string, bool) { return "", false })
	return c.fields
}

// Fields returns the recorded variables with secrets masked.
func (c *Config) Fields() []FieldDoc { return c.fields }

// Redacted returns the effective configuration as loggable key/value pairs,
// with secret values replaced. This is what the startup banner prints.
func (c *Config) Redacted() []FieldDoc {
	out := make([]FieldDoc, len(c.fields))
	copy(out, c.fields)
	return out
}

// IsProduction reports whether production defaults and checks apply.
func (c *Config) IsProduction() bool { return c.Env == EnvProduction }

func osLookup(key string) (string, bool) { return os.LookupEnv(key) }

func load(lookup func(string) (string, bool)) (*Config, error) {
	l := &loader{lookup: lookup}
	c := &Config{}

	c.Env = l.enum("AXT_ENV", EnvProduction,
		"Deployment environment. Development relaxes cookie and TLS expectations.",
		EnvProduction, EnvDevelopment)

	// --- HTTP -------------------------------------------------------------
	c.HTTP.Addr = l.str("AXT_HTTP_ADDR", ":8080",
		"Address the HTTP server listens on.")
	rawPublic := l.str("AXT_PUBLIC_URL", "http://localhost:8080",
		"External URL browsers use to reach AXT-Term. Determines cookie security and the default allowed origin.")
	originList := l.list("AXT_ALLOWED_ORIGINS", nil,
		"Comma-separated origins accepted for HTTP and WebSocket requests. Defaults to AXT_PUBLIC_URL's origin.")
	proxyList := l.list("AXT_TRUSTED_PROXIES", nil,
		"Comma-separated CIDRs whose X-Forwarded-For headers are trusted. Leave empty when no reverse proxy is in front.")
	c.HTTP.RequestTimeout = l.duration("AXT_REQUEST_TIMEOUT", 60*time.Second,
		"Timeout for regular API requests. Streaming and WebSocket routes are exempt.", time.Second)
	c.HTTP.ShutdownGrace = l.duration("AXT_SHUTDOWN_GRACE", 20*time.Second,
		"How long graceful shutdown may take before the process exits anyway.", time.Second)
	c.HTTP.MetricsEnabled = l.boolean("AXT_METRICS_ENABLED", false,
		"Expose Prometheus metrics at /metrics.")

	// --- Logging ----------------------------------------------------------
	c.Log.Level = l.enum("AXT_LOG_LEVEL", "info",
		"Minimum log level.", "debug", "info", "warn", "error")
	c.Log.Format = l.enum("AXT_LOG_FORMAT", "json",
		"Log output format.", "json", "text")

	// --- Paths ------------------------------------------------------------
	c.Paths.DataDir = l.str("AXT_DATA_DIR", "/var/lib/axt-term",
		"Directory holding the database, recordings, and other persistent state.")
	c.Paths.DBPath = l.str("AXT_DB_PATH", "",
		"SQLite database file. Defaults to $AXT_DATA_DIR/axt-term.db.")
	c.Paths.RecordingsDir = l.str("AXT_RECORDINGS_DIR", "",
		"Session recording directory. Defaults to $AXT_DATA_DIR/recordings.")

	// --- Security ---------------------------------------------------------
	c.Security.MasterKey = l.secretStr("AXT_MASTER_KEY",
		"Base64-encoded 32-byte key encrypting stored credentials. Provide exactly one of AXT_MASTER_KEY, AXT_MASTER_KEY_FILE, or AXT_MASTER_PASSPHRASE.")
	c.Security.MasterKeyFile = l.str("AXT_MASTER_KEY_FILE", "",
		"File containing the base64-encoded master key. Preferred over AXT_MASTER_KEY: file permissions beat environment inheritance.")
	c.Security.MasterPassphrase = l.secretStr("AXT_MASTER_PASSPHRASE",
		"Passphrase from which the master key is derived with Argon2id. Convenient, but weaker than a random key.")
	c.Security.SessionIdleTimeout = l.duration("AXT_SESSION_IDLE_TIMEOUT", 8*time.Hour,
		"Browser session expiry after inactivity.", time.Minute)
	c.Security.SessionMaxLifetime = l.duration("AXT_SESSION_MAX_LIFETIME", 168*time.Hour,
		"Absolute browser session lifetime regardless of activity.", time.Minute)

	// --- SSH --------------------------------------------------------------
	c.SSH.HostKeyPolicy = l.enum("AXT_SSH_HOSTKEY_POLICY", HostKeyPolicyTOFU,
		"How unknown SSH host keys are handled. 'tofu' prompts and pins; 'strict' rejects anything not already trusted. A mismatch always fails, under either policy.",
		HostKeyPolicyTOFU, HostKeyPolicyStrict)
	c.SSH.ConnectTimeout = l.duration("AXT_SSH_CONNECT_TIMEOUT", 15*time.Second,
		"Timeout for establishing one SSH hop.", time.Second)
	c.SSH.KeepaliveInterval = l.duration("AXT_SSH_KEEPALIVE_INTERVAL", 30*time.Second,
		"Interval between SSH keepalive requests, which stop NAT devices dropping idle sessions.", 5*time.Second)
	c.SSH.MaxHops = l.integer("AXT_SSH_MAX_HOPS", 5,
		"Maximum length of a jump-host chain.", 1, 16)
	c.SSH.LegacyAlgorithms = l.boolean("AXT_SSH_LEGACY_ALGOS", false,
		"Permit outdated ciphers and SHA-1 signatures, for network equipment that offers nothing better. Hosts using this are badged in the UI.")
	c.SSH.AgentSocket = l.str("AXT_SSH_AGENT_SOCKET", "",
		"Path to an SSH agent socket mounted into the container, enabling agent-based authentication.")

	// --- Sessions ---------------------------------------------------------
	c.Session.IdleClose = l.duration("AXT_SESSION_IDLE_CLOSE", 30*time.Minute,
		"How long a session with no attached browser is kept alive before closing.", time.Minute)
	c.Session.RingBufferSize = l.integer("AXT_SESSION_RING_BUFFER", 256*1024,
		"Per-session output buffer, in bytes, replayed when a browser reattaches. Larger survives longer disconnections at the cost of memory.", 4*1024, 16*1024*1024)
	c.Session.MaxPerUser = l.integer("AXT_MAX_SESSIONS_PER_USER", 50,
		"Maximum concurrent sessions one user may hold.", 1, 1000)
	c.Session.CommandLogging = l.enum("AXT_COMMAND_LOGGING", CommandLoggingCommands,
		"Default command-logging level, overridable per host. 'commands' records commands issued through the UI but not raw keystrokes; 'full' records entire sessions and should be treated as sensitive material.",
		CommandLoggingOff, CommandLoggingCommands, CommandLoggingFull)

	// --- Transfers and files ---------------------------------------------
	c.Transfer.Workers = l.integer("AXT_TRANSFER_WORKERS", 4,
		"Number of concurrent file transfers.", 1, 64)
	c.Transfer.UploadMaxBytes = l.integer64("AXT_UPLOAD_MAX_BYTES", 0,
		"Maximum single upload size in bytes. 0 means unlimited.", 0, 1<<50)
	c.Files.EditorMaxBytes = l.integer64("AXT_EDITOR_MAX_BYTES", 8*1024*1024,
		"Largest remote file the editor will open, in bytes.", 1024, 1<<30)

	// --- Tunnels and RDP -------------------------------------------------
	c.Tunnels.AllowPublicBind = l.boolean("AXT_TUNNEL_ALLOW_PUBLIC_BIND", false,
		"Allow tunnels to bind addresses other than loopback. Off by default so a forward cannot accidentally expose an internal service to the network.")
	c.RDP.GuacdAddr = l.str("AXT_GUACD_ADDR", "",
		"host:port of the guacd daemon. Empty disables RDP and VNC.")

	// --- Audit ------------------------------------------------------------
	c.Audit.RetentionDays = l.integer("AXT_AUDIT_RETENTION_DAYS", 0,
		"Days of audit history to retain. 0 retains indefinitely; pruning is an explicit admin action.", 0, 36500)

	// --- Rate limits ------------------------------------------------------
	c.RateLimit.LoginPerIP = l.integer("AXT_RATELIMIT_LOGIN_PER_IP", 5,
		"Login attempts allowed per IP per window.", 1, 1000)
	c.RateLimit.LoginPerUser = l.integer("AXT_RATELIMIT_LOGIN_PER_USER", 10,
		"Login attempts allowed per username per window.", 1, 1000)
	c.RateLimit.LoginWindow = l.duration("AXT_RATELIMIT_LOGIN_WINDOW", 5*time.Minute,
		"Window over which login attempts are counted.", 10*time.Second)
	c.RateLimit.LockoutThreshold = l.integer("AXT_LOCKOUT_THRESHOLD", 10,
		"Consecutive failed logins before an account locks.", 1, 1000)
	c.RateLimit.LockoutDuration = l.duration("AXT_LOCKOUT_DURATION", 15*time.Minute,
		"How long an account stays locked.", time.Minute)
	c.RateLimit.GeneralPerMinute = l.integer("AXT_RATELIMIT_PER_MINUTE", 600,
		"General API requests allowed per user per minute.", 10, 100000)
	c.RateLimit.GeneralBurst = l.integer("AXT_RATELIMIT_BURST", 60,
		"General API burst allowance.", 1, 10000)
	c.RateLimit.SessionCreatePerMin = l.integer("AXT_RATELIMIT_SESSIONS_PER_MINUTE", 30,
		"Session creations allowed per user per minute.", 1, 10000)
	c.RateLimit.TicketPerMinute = l.integer("AXT_RATELIMIT_TICKETS_PER_MINUTE", 60,
		"WebSocket tickets issued per user per minute.", 1, 10000)
	c.RateLimit.DiscoveryConcurrency = l.integer("AXT_DISCOVERY_CONCURRENCY", 1,
		"Concurrent network discovery scans allowed per user.", 1, 8)

	// --- Derived and cross-field resolution ------------------------------
	if u, err := parsePublicURL(rawPublic); err != nil {
		l.fail("AXT_PUBLIC_URL: %v", err)
	} else {
		c.HTTP.PublicURL = u
		c.Security.CookieSecure = u.Scheme == "https"
	}

	if len(originList) == 0 {
		if c.HTTP.PublicURL != nil {
			c.HTTP.AllowedOrigins = []string{originOf(c.HTTP.PublicURL)}
		}
	} else {
		for _, raw := range originList {
			u, err := parsePublicURL(raw)
			if err != nil {
				l.fail("AXT_ALLOWED_ORIGINS: %q: %v", raw, err)
				continue
			}
			c.HTTP.AllowedOrigins = append(c.HTTP.AllowedOrigins, originOf(u))
		}
	}

	for _, raw := range proxyList {
		p, err := parsePrefix(raw)
		if err != nil {
			l.fail("AXT_TRUSTED_PROXIES: %q: %v", raw, err)
			continue
		}
		c.HTTP.TrustedProxies = append(c.HTTP.TrustedProxies, p)
	}

	if _, _, err := net.SplitHostPort(c.HTTP.Addr); err != nil {
		l.fail("AXT_HTTP_ADDR: %q is not a valid host:port", c.HTTP.Addr)
	}

	if c.Paths.DBPath == "" {
		c.Paths.DBPath = filepath.Join(c.Paths.DataDir, "axt-term.db")
	}
	if c.Paths.RecordingsDir == "" {
		c.Paths.RecordingsDir = filepath.Join(c.Paths.DataDir, "recordings")
	}

	if c.Security.SessionMaxLifetime < c.Security.SessionIdleTimeout {
		l.fail("AXT_SESSION_MAX_LIFETIME (%s) must be at least AXT_SESSION_IDLE_TIMEOUT (%s)",
			c.Security.SessionMaxLifetime, c.Security.SessionIdleTimeout)
	}

	if c.RateLimit.GeneralBurst > c.RateLimit.GeneralPerMinute {
		l.fail("AXT_RATELIMIT_BURST (%d) must not exceed AXT_RATELIMIT_PER_MINUTE (%d)",
			c.RateLimit.GeneralBurst, c.RateLimit.GeneralPerMinute)
	}

	c.fields = l.fields
	if len(l.errs) > 0 {
		return c, fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errStrings(l.errs), "\n  - "))
	}
	return c, nil
}

// Warnings returns non-fatal configuration concerns worth logging at startup.
// These are deliberately not errors: an operator may be behind a TLS-terminating
// proxy we cannot see, and refusing to start would be wrong.
func (c *Config) Warnings() []string {
	var w []string
	if c.IsProduction() && !c.Security.CookieSecure {
		w = append(w, "AXT_PUBLIC_URL is not https: session cookies cannot use the Secure attribute or the __Host- prefix, and credentials will cross the network in clear text unless a TLS-terminating proxy sits in front")
	}
	if !c.RDP.Enabled() {
		w = append(w, "AXT_GUACD_ADDR is unset: RDP and VNC connections are unavailable")
	}
	if c.SSH.HostKeyPolicy == HostKeyPolicyTOFU && c.IsProduction() {
		w = append(w, "AXT_SSH_HOSTKEY_POLICY is 'tofu': unknown host keys are accepted after an interactive prompt. Consider 'strict' once your inventory's keys are trusted")
	}
	if c.SSH.LegacyAlgorithms {
		w = append(w, "AXT_SSH_LEGACY_ALGOS is enabled: outdated ciphers and SHA-1 signatures are permitted")
	}
	if c.Tunnels.AllowPublicBind {
		w = append(w, "AXT_TUNNEL_ALLOW_PUBLIC_BIND is enabled: tunnels may expose forwarded services beyond loopback")
	}
	if c.Session.CommandLogging == CommandLoggingFull {
		w = append(w, "AXT_COMMAND_LOGGING is 'full': complete session output is recorded to disk. Recordings routinely contain secrets and must be protected accordingly")
	}
	if len(c.HTTP.TrustedProxies) == 0 && c.IsProduction() {
		w = append(w, "AXT_TRUSTED_PROXIES is empty: X-Forwarded-For is ignored, so audit entries will record the proxy's address rather than the client's")
	}
	return w
}

func parsePublicURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("scheme must be http or https")
	}
	if u.Host == "" {
		return nil, errors.New("missing host")
	}
	return u, nil
}

// originOf renders a URL as an RFC 6454 origin for comparison against the
// browser's Origin header.
func originOf(u *url.URL) string { return u.Scheme + "://" + u.Host }

// parsePrefix accepts either a CIDR ("10.0.0.0/8") or a bare address, which is
// treated as a single-host prefix.
func parsePrefix(raw string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(raw); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, errors.New("not an IP address or CIDR")
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func errStrings(errs []error) []string {
	out := make([]string, len(errs))
	for i, e := range errs {
		out[i] = e.Error()
	}
	return out
}

// loader reads and records environment variables, accumulating errors.
type loader struct {
	lookup func(string) (string, bool)
	errs   []error
	fields []FieldDoc
}

func (l *loader) fail(format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf(format, args...))
}

func (l *loader) raw(key string) (string, bool) {
	v, ok := l.lookup(key)
	if !ok {
		return "", false
	}
	if v = strings.TrimSpace(v); v == "" {
		return "", false
	}
	return v, true
}

func (l *loader) record(f FieldDoc) { l.fields = append(l.fields, f) }

func (l *loader) str(key, def, doc string) string {
	v, ok := l.raw(key)
	if !ok {
		v = def
	}
	l.record(FieldDoc{Key: key, Value: v, Default: def, Doc: doc, Kind: "string"})
	return v
}

func (l *loader) secretStr(key, doc string) string {
	v, ok := l.raw(key)
	shown := ""
	if ok {
		shown = "[set]"
	}
	l.record(FieldDoc{Key: key, Value: shown, Doc: doc, Kind: "string", Secret: true})
	return v
}

func (l *loader) enum(key, def, doc string, allowed ...string) string {
	v, ok := l.raw(key)
	switch {
	case !ok:
		v = def
	default:
		valid := false
		for _, a := range allowed {
			if v == a {
				valid = true
				break
			}
		}
		if !valid {
			l.fail("%s: %q is not one of: %s", key, v, strings.Join(allowed, ", "))
			v = def
		}
	}
	l.record(FieldDoc{Key: key, Value: v, Default: def, Doc: doc, Kind: "enum", Allowed: allowed})
	return v
}

func (l *loader) boolean(key string, def bool, doc string) bool {
	v := def
	if raw, ok := l.raw(key); ok {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			l.fail("%s: %q is not a boolean (use true or false)", key, raw)
		} else {
			v = parsed
		}
	}
	l.record(FieldDoc{Key: key, Value: strconv.FormatBool(v), Default: strconv.FormatBool(def), Doc: doc, Kind: "bool"})
	return v
}

func (l *loader) integer(key string, def int, doc string, minVal, maxVal int) int {
	return int(l.integer64(key, int64(def), doc, int64(minVal), int64(maxVal)))
}

func (l *loader) integer64(key string, def int64, doc string, minVal, maxVal int64) int64 {
	v := def
	if raw, ok := l.raw(key); ok {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		switch {
		case err != nil:
			l.fail("%s: %q is not an integer", key, raw)
		case parsed < minVal || parsed > maxVal:
			l.fail("%s: %d is out of range [%d, %d]", key, parsed, minVal, maxVal)
		default:
			v = parsed
		}
	}
	l.record(FieldDoc{
		Key: key, Value: strconv.FormatInt(v, 10), Default: strconv.FormatInt(def, 10),
		Doc: doc, Kind: fmt.Sprintf("int [%d..%d]", minVal, maxVal),
	})
	return v
}

func (l *loader) duration(key string, def time.Duration, doc string, minVal time.Duration) time.Duration {
	v := def
	if raw, ok := l.raw(key); ok {
		parsed, err := time.ParseDuration(raw)
		switch {
		case err != nil:
			l.fail("%s: %q is not a duration (examples: 30s, 15m, 8h)", key, raw)
		case parsed < minVal:
			l.fail("%s: %s is below the minimum of %s", key, parsed, minVal)
		default:
			v = parsed
		}
	}
	l.record(FieldDoc{Key: key, Value: v.String(), Default: def.String(), Doc: doc, Kind: "duration"})
	return v
}

func (l *loader) list(key string, def []string, doc string) []string {
	v := def
	if raw, ok := l.raw(key); ok {
		v = nil
		for _, part := range strings.Split(raw, ",") {
			if part = strings.TrimSpace(part); part != "" {
				v = append(v, part)
			}
		}
	}
	l.record(FieldDoc{Key: key, Value: strings.Join(v, ","), Default: strings.Join(def, ","), Doc: doc, Kind: "list"})
	return v
}
