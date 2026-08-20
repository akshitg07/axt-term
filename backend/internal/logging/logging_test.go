package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func newTestLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	log, err := New(Options{Level: "debug", Format: "json", Output: &buf})
	if err != nil {
		t.Fatal(err)
	}
	return log, &buf
}

func TestSensitiveAttributesAreRedacted(t *testing.T) {
	t.Parallel()

	const secret = "hunter2-do-not-log-me"
	log, buf := newTestLogger(t)

	log.Info("connecting",
		slog.String("password", secret),
		slog.String("passphrase", secret),
		slog.String("ssh_private_key", secret),
		slog.String("ticket", secret),
		slog.String("csrf", secret),
		slog.String("authorization", "Bearer "+secret),
		slog.String("kubeconfig", secret),
	)

	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret survived scrubbing:\n%s", out)
	}
	if n := strings.Count(out, Redacted); n < 7 {
		t.Errorf("expected 7 redactions, found %d:\n%s", n, out)
	}
}

// Over-redacting is its own failure: these fields are what make an incident
// diagnosable, and none of them is a secret.
func TestLoggableFieldsSurvive(t *testing.T) {
	t.Parallel()

	log, buf := newTestLogger(t)
	log.Info("session opened",
		slog.String("host_key", "ssh-ed25519"),
		slog.String("public_key", "AAAAC3NzaC1lZDI1NTE5"),
		slog.String("key_type", "ed25519"),
		slog.String("key_fingerprint", "SHA256:abc123"),
		slog.String("credential_id", "018f-credential"),
		slog.String("session_id", "018f-session"),
		slog.String("key", "ui.theme"),
		slog.String("username", "akshit"),
		slog.String("hostname", "prod-web01"),
	)

	out := buf.String()
	for _, want := range []string{
		"ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5", "ed25519", "SHA256:abc123",
		"018f-credential", "018f-session", "ui.theme", "akshit", "prod-web01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("%q was redacted but is not a secret:\n%s", want, out)
		}
	}
	if strings.Contains(out, Redacted) {
		t.Errorf("nothing should have been redacted:\n%s", out)
	}
}

func TestGroupedAttributesAreScrubbedRecursively(t *testing.T) {
	t.Parallel()

	const secret = "nested-secret-value"
	log, buf := newTestLogger(t)

	log.Info("credential verified",
		slog.Group("credential",
			slog.String("id", "cred-1"),
			slog.String("password", secret),
			slog.Group("ssh",
				slog.String("private_key", secret),
				slog.String("key_type", "rsa"),
			),
		),
	)

	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret survived inside a group:\n%s", out)
	}
	if !strings.Contains(out, "cred-1") || !strings.Contains(out, "rsa") {
		t.Errorf("non-secret group members were lost:\n%s", out)
	}
}

// WithAttrs is how request-scoped loggers are built, so it must scrub too --
// otherwise a secret attached once leaks on every subsequent line.
func TestWithAttrsScrubs(t *testing.T) {
	t.Parallel()

	const secret = "bound-once-leaked-forever"
	log, buf := newTestLogger(t)

	scoped := log.With(slog.String("session_token", secret), slog.String("request_id", "req-9"))
	scoped.Info("first")
	scoped.Info("second")

	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret bound via With leaked:\n%s", out)
	}
	if strings.Count(out, "req-9") != 2 {
		t.Errorf("bound non-secret attributes should persist:\n%s", out)
	}
}

func TestWithGroupPreservesScrubbing(t *testing.T) {
	t.Parallel()

	const secret = "grouped-handler-secret"
	log, buf := newTestLogger(t)

	log.WithGroup("auth").Info("attempt", slog.String("password", secret))

	if out := buf.String(); strings.Contains(out, secret) {
		t.Fatalf("secret leaked through WithGroup:\n%s", out)
	}
}

func TestScrubStringPatterns(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		in        string
		mustNotHave string
		mustHave  string
	}{
		{
			name:      "websocket ticket in url",
			in:        "GET /ws/terminal?session=abc&ticket=9f8a7b6c5d4e3f2a1b0c HTTP/1.1",
			mustNotHave: "9f8a7b6c5d4e3f2a1b0c",
			mustHave:  "/ws/terminal?session=abc&ticket=",
		},
		{
			name:      "bearer token",
			in:        "upstream rejected: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
			mustNotHave: "eyJhbGciOiJIUzI1NiJ9",
			mustHave:  "upstream rejected",
		},
		{
			name:        "basic auth",
			in:          `proxy said: Authorization: Basic YWtzaGl0OnN1cGVyc2VjcmV0`,
			mustNotHave: "YWtzaGl0OnN1cGVyc2VjcmV0",
			mustHave:    "proxy said",
		},
		{
			name:      "inline assignment",
			in:        `mysql: connecting with password=s3cr3tvalue to db`,
			mustNotHave: "s3cr3tvalue",
			mustHave:  "mysql: connecting with",
		},
		{
			name: "pem private key",
			in: "key load failed:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nsecretmaterialhere\n-----END OPENSSH PRIVATE KEY-----\nafter",
			mustNotHave: "secretmaterialhere",
			mustHave:  "key load failed:",
		},
		{
			name:      "ordinary message untouched",
			in:        "dial tcp 10.0.4.12:22: connect: connection refused",
			mustNotHave: "[redacted]",
			mustHave:  "connection refused",
		},
	} {
		got := ScrubString(tc.in)
		if tc.mustNotHave != "" && strings.Contains(got, tc.mustNotHave) {
			t.Errorf("%s: %q survived in %q", tc.name, tc.mustNotHave, got)
		}
		if tc.mustHave != "" && !strings.Contains(got, tc.mustHave) {
			t.Errorf("%s: %q was lost from %q", tc.name, tc.mustHave, got)
		}
	}
}

func TestMessagesAreScrubbedNotJustAttributes(t *testing.T) {
	t.Parallel()

	log, buf := newTestLogger(t)
	log.Error("ws upgrade failed for /ws/terminal?ticket=leaked-ticket-value")

	out := buf.String()
	if strings.Contains(out, "leaked-ticket-value") {
		t.Fatalf("ticket leaked through the message:\n%s", out)
	}
	if !strings.Contains(out, "ws upgrade failed") {
		t.Errorf("message text was lost:\n%s", out)
	}
}

func TestOutputIsValidJSON(t *testing.T) {
	t.Parallel()

	log, buf := newTestLogger(t)
	log.Info("hello", slog.String("password", "x"), slog.Int("count", 3))

	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("scrubbing must not corrupt JSON output: %v\n%s", err, buf.String())
	}
	if got["password"] != Redacted {
		t.Errorf("password = %v, want %q", got["password"], Redacted)
	}
	if got["count"] != float64(3) {
		t.Errorf("count = %v, want 3", got["count"])
	}
	if got["msg"] != "hello" {
		t.Errorf("msg = %v", got["msg"])
	}
}

func TestLevelFiltering(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log, err := New(Options{Level: "warn", Format: "text", Output: &buf})
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("debug line")
	log.Info("info line")
	log.Warn("warn line")

	out := buf.String()
	if strings.Contains(out, "debug line") || strings.Contains(out, "info line") {
		t.Errorf("level filtering failed:\n%s", out)
	}
	if !strings.Contains(out, "warn line") {
		t.Errorf("warn should pass:\n%s", out)
	}
}

func TestParseLevelRejectsUnknown(t *testing.T) {
	t.Parallel()

	if _, err := ParseLevel("verbose"); err == nil {
		t.Error("expected an error for an unknown level")
	}
	if _, err := New(Options{Format: "yaml"}); err == nil {
		t.Error("expected an error for an unknown format")
	}
}

func TestIsSensitiveKey(t *testing.T) {
	t.Parallel()

	sensitive := []string{
		"password", "PASSWORD", "passphrase", "secret", "token", "ticket",
		"private_key", "ssh_private_key", "admin_password", "csrf",
		"authorization", "cookie", "api_key", "vault_token",
	}
	for _, k := range sensitive {
		if !IsSensitiveKey(k) {
			t.Errorf("%q should be treated as sensitive", k)
		}
	}

	safe := []string{
		"key", "key_type", "host_key", "public_key", "key_fingerprint",
		"credential_id", "session_id", "username", "hostname", "token_count",
	}
	for _, k := range safe {
		if IsSensitiveKey(k) {
			t.Errorf("%q should not be treated as sensitive", k)
		}
	}
}
