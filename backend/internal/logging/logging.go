// Package logging configures structured logging for AXT-Term.
//
// The notable piece is ScrubHandler. AXT-Term holds SSH private keys, RDP
// passwords, and session tickets, and a log file is a second store that is
// backed up, shipped to aggregators, and read by more people than the database.
// Discipline alone ("never log a secret") fails eventually, so a handler sits
// in the path and removes the obvious cases regardless of what a caller did.
//
// Scrubbing is defence in depth, not a licence to pass secrets to the logger.
// It cannot recognise a secret in an arbitrary string, and TestNoSecretsInLogs
// in the security suite is what actually asserts the codebase behaves.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

// Redacted replaces any value the scrubber removes.
const Redacted = "[redacted]"

// Options configures a logger.
type Options struct {
	Level     string    // debug, info, warn, error
	Format    string    // json, text
	Output    io.Writer // defaults to os.Stderr
	AddSource bool
}

// New builds a logger that scrubs known-sensitive attributes.
func New(opts Options) (*slog.Logger, error) {
	level, err := ParseLevel(opts.Level)
	if err != nil {
		return nil, err
	}
	out := opts.Output
	if out == nil {
		out = os.Stderr
	}

	handlerOpts := &slog.HandlerOptions{Level: level, AddSource: opts.AddSource}

	var base slog.Handler
	switch strings.ToLower(opts.Format) {
	case "", "json":
		base = slog.NewJSONHandler(out, handlerOpts)
	case "text":
		base = slog.NewTextHandler(out, handlerOpts)
	default:
		return nil, fmt.Errorf("unknown log format %q (want json or text)", opts.Format)
	}

	return slog.New(ScrubHandler{inner: base}), nil
}

// Discard returns a logger that writes nowhere, for tests that do not assert on
// output.
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// ParseLevel maps a configuration string to a slog level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q (want debug, info, warn, or error)", s)
	}
}

// ScrubHandler wraps a slog.Handler and redacts sensitive attributes and
// recognisable secret patterns before they reach the output.
type ScrubHandler struct {
	inner slog.Handler
}

// NewScrubHandler wraps an existing handler.
func NewScrubHandler(inner slog.Handler) ScrubHandler { return ScrubHandler{inner: inner} }

// Enabled implements slog.Handler.
func (h ScrubHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle implements slog.Handler.
func (h ScrubHandler) Handle(ctx context.Context, rec slog.Record) error {
	scrubbed := slog.NewRecord(rec.Time, rec.Level, ScrubString(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		scrubbed.AddAttrs(scrubAttr(a))
		return true
	})
	return h.inner.Handle(ctx, scrubbed)
}

// WithAttrs implements slog.Handler.
func (h ScrubHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = scrubAttr(a)
	}
	return ScrubHandler{inner: h.inner.WithAttrs(out)}
}

// WithGroup implements slog.Handler.
func (h ScrubHandler) WithGroup(name string) slog.Handler {
	return ScrubHandler{inner: h.inner.WithGroup(name)}
}

func scrubAttr(a slog.Attr) slog.Attr {
	a.Value = a.Value.Resolve()

	if IsSensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}

	switch a.Value.Kind() {
	case slog.KindGroup:
		group := a.Value.Group()
		out := make([]slog.Attr, len(group))
		for i, member := range group {
			out[i] = scrubAttr(member)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	case slog.KindString:
		return slog.String(a.Key, ScrubString(a.Value.String()))
	default:
		return a
	}
}

// Attribute names whose values are always removed. Deliberately specific:
// "key" alone is not listed because settings keys, key types, host keys, and
// key fingerprints are all legitimately loggable and all contain it.
var sensitiveExact = map[string]struct{}{
	"password":      {},
	"passwd":        {},
	"passphrase":    {},
	"secret":        {},
	"token":         {},
	"ticket":        {},
	"authorization": {},
	"cookie":        {},
	"set-cookie":    {},
	"csrf":          {},
	"private_key":   {},
	"privatekey":    {},
	"master_key":    {},
	"masterkey":     {},
	"api_key":       {},
	"apikey":        {},
	"bearer":        {},
	"kubeconfig":    {},
	"dek":           {},
	"kek":           {},
	"plaintext":     {},
}

var sensitiveSuffixes = []string{
	"_password",
	"_passphrase",
	"_secret",
	"_token",
	"_ticket",
	"_private_key",
	"_api_key",
	"_apikey",
	"_key_material",
}

// IsSensitiveKey reports whether an attribute name always has its value removed.
func IsSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if _, ok := sensitiveExact[k]; ok {
		return true
	}
	for _, suffix := range sensitiveSuffixes {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}

var (
	// PEM private key blocks, however they were embedded.
	pemPrivateKeyRe = regexp.MustCompile(
		`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

	// Query parameters carrying credentials or tickets. WebSocket URLs pass
	// tickets this way, so access logs would otherwise record them.
	sensitiveQueryRe = regexp.MustCompile(
		`(?i)([?&](?:ticket|token|access_token|password|passphrase|secret|key)=)[^&\s"]+`)

	// Authorization header values that reached a log line.
	bearerRe = regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}`)
	basicRe  = regexp.MustCompile(`(?i)\b(basic\s+)[A-Za-z0-9+/=]{8,}`)

	// "password: hunter2" style output, which appears when a remote command's
	// stderr is logged.
	inlineAssignmentRe = regexp.MustCompile(
		`(?i)\b(password|passwd|passphrase|secret|token)\s*[:=]\s*("[^"]*"|'[^']*'|\S+)`)
)

// ScrubString removes recognisable secrets from a free-text value.
//
// The patterns are high-confidence by design: over-redacting log messages
// destroys the diagnostics that make an incident tractable, so anything
// ambiguous is left alone and handled by not logging it in the first place.
func ScrubString(s string) string {
	if s == "" {
		return s
	}
	if strings.Contains(s, "PRIVATE KEY") {
		s = pemPrivateKeyRe.ReplaceAllString(s, "[redacted private key]")
	}
	if strings.ContainsAny(s, "?&") {
		s = sensitiveQueryRe.ReplaceAllString(s, "${1}"+Redacted)
	}
	s = bearerRe.ReplaceAllString(s, "${1}"+Redacted)
	s = basicRe.ReplaceAllString(s, "${1}"+Redacted)
	s = inlineAssignmentRe.ReplaceAllString(s, "${1}="+Redacted)
	return s
}
