package config

import (
	"strings"
	"testing"
	"time"
)

// env builds a lookup function over a literal map, so tests never touch the
// real process environment and can run in parallel.
func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	c, err := load(env(nil))
	if err != nil {
		t.Fatalf("defaults must load cleanly, got: %v", err)
	}

	if c.Env != EnvProduction {
		t.Errorf("Env = %q, want %q", c.Env, EnvProduction)
	}
	if c.HTTP.Addr != ":8080" {
		t.Errorf("HTTP.Addr = %q", c.HTTP.Addr)
	}
	if got, want := c.Paths.DBPath, "/var/lib/axt-term/axt-term.db"; got != want {
		t.Errorf("DBPath = %q, want %q", got, want)
	}
	if got, want := c.Paths.RecordingsDir, "/var/lib/axt-term/recordings"; got != want {
		t.Errorf("RecordingsDir = %q, want %q", got, want)
	}
	if c.SSH.HostKeyPolicy != HostKeyPolicyTOFU {
		t.Errorf("HostKeyPolicy = %q", c.SSH.HostKeyPolicy)
	}
	if c.Session.CommandLogging != CommandLoggingCommands {
		t.Errorf("CommandLogging = %q", c.Session.CommandLogging)
	}
	if c.Tunnels.AllowPublicBind {
		t.Error("tunnels must not bind publicly by default")
	}
	if c.RDP.Enabled() {
		t.Error("RDP must be disabled when AXT_GUACD_ADDR is unset")
	}
}

// A plain-HTTP public URL must not produce Secure cookies: browsers reject
// them, and every login would fail with no useful error.
func TestCookieSecureFollowsScheme(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		url        string
		wantSecure bool
		wantOrigin string
	}{
		{"https://axt.example.com", true, "https://axt.example.com"},
		{"http://localhost:8080", false, "http://localhost:8080"},
		{"https://axt.example.com:8443/", true, "https://axt.example.com:8443"},
	} {
		c, err := load(env(map[string]string{"AXT_PUBLIC_URL": tc.url}))
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		if c.Security.CookieSecure != tc.wantSecure {
			t.Errorf("%s: CookieSecure = %v, want %v", tc.url, c.Security.CookieSecure, tc.wantSecure)
		}
		if got := c.HTTP.AllowedOrigins; len(got) != 1 || got[0] != tc.wantOrigin {
			t.Errorf("%s: AllowedOrigins = %v, want [%s]", tc.url, got, tc.wantOrigin)
		}
	}
}

func TestAllowedOriginsExplicit(t *testing.T) {
	t.Parallel()

	c, err := load(env(map[string]string{
		"AXT_PUBLIC_URL":      "https://axt.example.com",
		"AXT_ALLOWED_ORIGINS": "https://axt.example.com, https://ops.example.com:8443",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://axt.example.com", "https://ops.example.com:8443"}
	if len(c.HTTP.AllowedOrigins) != len(want) {
		t.Fatalf("AllowedOrigins = %v, want %v", c.HTTP.AllowedOrigins, want)
	}
	for i := range want {
		if c.HTTP.AllowedOrigins[i] != want[i] {
			t.Errorf("AllowedOrigins[%d] = %q, want %q", i, c.HTTP.AllowedOrigins[i], want[i])
		}
	}
}

func TestTrustedProxiesAcceptsCIDRAndBareAddress(t *testing.T) {
	t.Parallel()

	c, err := load(env(map[string]string{
		"AXT_TRUSTED_PROXIES": "10.0.0.0/8, 172.18.0.3, ::1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.HTTP.TrustedProxies) != 3 {
		t.Fatalf("TrustedProxies = %v, want 3 entries", c.HTTP.TrustedProxies)
	}
	// A bare address must become a single-host prefix, not a wildcard.
	if bits := c.HTTP.TrustedProxies[1].Bits(); bits != 32 {
		t.Errorf("bare IPv4 prefix bits = %d, want 32", bits)
	}
	if bits := c.HTTP.TrustedProxies[2].Bits(); bits != 128 {
		t.Errorf("bare IPv6 prefix bits = %d, want 128", bits)
	}
}

// Every problem must be reported at once. Discovering configuration errors one
// restart at a time is the failure mode this test guards against.
func TestLoadReportsAllErrorsTogether(t *testing.T) {
	t.Parallel()

	_, err := load(env(map[string]string{
		"AXT_LOG_LEVEL":            "verbose",     // not an allowed enum value
		"AXT_SHUTDOWN_GRACE":       "soon",        // not a duration
		"AXT_TRANSFER_WORKERS":     "9000",        // out of range
		"AXT_HTTP_ADDR":            "not-an-addr", // no port
		"AXT_PUBLIC_URL":           "ftp://x",     // wrong scheme
		"AXT_METRICS_ENABLED":      "perhaps",     // not a bool
		"AXT_SSH_CONNECT_TIMEOUT":  "1ms",         // below minimum
		"AXT_TRUSTED_PROXIES":      "10.0.0.0/8, nonsense",
		"AXT_SESSION_RING_BUFFER":  "128", // below minimum
		"AXT_RATELIMIT_PER_MINUTE": "10",
		"AXT_RATELIMIT_BURST":      "60", // exceeds per-minute
	}))
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, want := range []string{
		"AXT_LOG_LEVEL", "AXT_SHUTDOWN_GRACE", "AXT_TRANSFER_WORKERS",
		"AXT_HTTP_ADDR", "AXT_PUBLIC_URL", "AXT_METRICS_ENABLED",
		"AXT_SSH_CONNECT_TIMEOUT", "AXT_TRUSTED_PROXIES",
		"AXT_SESSION_RING_BUFFER", "AXT_RATELIMIT_BURST",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message is missing %s:\n%s", want, msg)
		}
	}
}

func TestSessionLifetimeMustExceedIdleTimeout(t *testing.T) {
	t.Parallel()

	_, err := load(env(map[string]string{
		"AXT_SESSION_IDLE_TIMEOUT": "48h",
		"AXT_SESSION_MAX_LIFETIME": "24h",
	}))
	if err == nil || !strings.Contains(err.Error(), "AXT_SESSION_MAX_LIFETIME") {
		t.Fatalf("expected a lifetime/idle-timeout conflict, got: %v", err)
	}
}

func TestOverridesApply(t *testing.T) {
	t.Parallel()

	c, err := load(env(map[string]string{
		"AXT_ENV":                      "development",
		"AXT_DATA_DIR":                 "/srv/axt",
		"AXT_DB_PATH":                  "/srv/custom.db",
		"AXT_SESSION_IDLE_CLOSE":       "5m",
		"AXT_GUACD_ADDR":               "guacd:4822",
		"AXT_TUNNEL_ALLOW_PUBLIC_BIND": "true",
		"AXT_UPLOAD_MAX_BYTES":         "1073741824",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Env != EnvDevelopment {
		t.Errorf("Env = %q", c.Env)
	}
	if c.Paths.DBPath != "/srv/custom.db" {
		t.Errorf("explicit DBPath must win: %q", c.Paths.DBPath)
	}
	if c.Paths.RecordingsDir != "/srv/axt/recordings" {
		t.Errorf("RecordingsDir should derive from DataDir: %q", c.Paths.RecordingsDir)
	}
	if c.Session.IdleClose != 5*time.Minute {
		t.Errorf("IdleClose = %s", c.Session.IdleClose)
	}
	if !c.RDP.Enabled() {
		t.Error("RDP should be enabled once guacd is configured")
	}
	if c.Transfer.UploadMaxBytes != 1<<30 {
		t.Errorf("UploadMaxBytes = %d", c.Transfer.UploadMaxBytes)
	}
}

// The startup banner is logged. It must never carry a secret.
func TestRedactedNeverExposesSecrets(t *testing.T) {
	t.Parallel()

	const (
		key        = "c2VjcmV0LW1hc3Rlci1rZXktMzItYnl0ZXMtbG9uZyE="
		passphrase = "correct horse battery staple"
	)
	c, err := load(env(map[string]string{
		"AXT_MASTER_KEY":        key,
		"AXT_MASTER_PASSPHRASE": passphrase,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Security.MasterKey != key {
		t.Error("the loaded value must still be usable in-process")
	}

	var sawMasterKey, sawPassphrase bool
	for _, f := range c.Redacted() {
		if strings.Contains(f.Value, key) || strings.Contains(f.Value, passphrase) {
			t.Fatalf("%s leaked its value: %q", f.Key, f.Value)
		}
		if strings.Contains(f.Doc, key) || strings.Contains(f.Doc, passphrase) {
			t.Fatalf("%s leaked its value through documentation", f.Key)
		}
		switch f.Key {
		case "AXT_MASTER_KEY":
			sawMasterKey = true
			if !f.Secret {
				t.Error("AXT_MASTER_KEY must be marked secret")
			}
			if f.Value != "[set]" {
				t.Errorf("AXT_MASTER_KEY value = %q, want [set]", f.Value)
			}
		case "AXT_MASTER_PASSPHRASE":
			sawPassphrase = true
			if !f.Secret {
				t.Error("AXT_MASTER_PASSPHRASE must be marked secret")
			}
		}
	}
	if !sawMasterKey || !sawPassphrase {
		t.Error("secret fields must appear in the redacted banner, masked")
	}
}

func TestDescribeDocumentsEveryVariable(t *testing.T) {
	t.Parallel()

	fields := Describe()
	if len(fields) < 30 {
		t.Fatalf("Describe returned only %d fields; the reference docs would be incomplete", len(fields))
	}

	seen := make(map[string]bool, len(fields))
	for _, f := range fields {
		if !strings.HasPrefix(f.Key, "AXT_") {
			t.Errorf("%q does not use the AXT_ prefix", f.Key)
		}
		if seen[f.Key] {
			t.Errorf("%s is recorded twice", f.Key)
		}
		seen[f.Key] = true
		if strings.TrimSpace(f.Doc) == "" {
			t.Errorf("%s has no documentation", f.Key)
		}
		if f.Kind == "enum" && len(f.Allowed) == 0 {
			t.Errorf("%s is an enum with no allowed values", f.Key)
		}
	}
}

func TestWarningsFlagRiskyProductionSettings(t *testing.T) {
	t.Parallel()

	c, err := load(env(map[string]string{
		"AXT_PUBLIC_URL":               "http://axt.internal",
		"AXT_SSH_LEGACY_ALGOS":         "true",
		"AXT_TUNNEL_ALLOW_PUBLIC_BIND": "true",
		"AXT_COMMAND_LOGGING":          "full",
	}))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(c.Warnings(), "\n")
	for _, want := range []string{
		"AXT_PUBLIC_URL", "AXT_SSH_LEGACY_ALGOS",
		"AXT_TUNNEL_ALLOW_PUBLIC_BIND", "AXT_COMMAND_LOGGING",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings omit %s:\n%s", want, joined)
		}
	}
}

func TestDevelopmentSuppressesTLSWarning(t *testing.T) {
	t.Parallel()

	c, err := load(env(map[string]string{
		"AXT_ENV":        "development",
		"AXT_PUBLIC_URL": "http://localhost:5173",
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range c.Warnings() {
		if strings.Contains(w, "AXT_PUBLIC_URL") {
			t.Errorf("development should not warn about plain HTTP: %q", w)
		}
	}
}
