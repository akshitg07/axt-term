package httpx

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/axt-term/axt-term/backend/internal/logging"
)

// RequestIDHeader carries the correlation identifier in and out.
const RequestIDHeader = "X-Request-Id"

// safeRequestID limits what an inbound identifier may contain, so a client
// cannot inject newlines or control characters into log lines through it.
var safeRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

// AssignRequestID attaches a correlation identifier to the request and echoes it
// in the response. An inbound identifier is honoured when it is well-formed, so
// traces survive a reverse proxy that already assigned one.
func AssignRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if !safeRequestID.MatchString(id) {
			id = newID()
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(WithRequestID(r.Context(), id)))
	})
}

// RealIP resolves the client address, consulting X-Forwarded-For only when the
// immediate peer is a trusted proxy.
//
// Trusting the header unconditionally would let any client forge the address
// recorded in the audit log and defeat per-IP rate limiting, so with no trusted
// proxies configured the header is ignored entirely.
func RealIP(trusted []netip.Prefix) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := resolveClientIP(r, trusted)
			next.ServeHTTP(w, r.WithContext(WithClientIP(r.Context(), ip)))
		})
	}
}

func resolveClientIP(r *http.Request, trusted []netip.Prefix) string {
	peer, ok := peerAddr(r.RemoteAddr)
	if !ok {
		return r.RemoteAddr
	}
	if len(trusted) == 0 || !addrInAny(peer, trusted) {
		return peer.String()
	}

	// The peer is a trusted proxy, so walk the forwarded chain from the right
	// (nearest) towards the left (original client) and take the first address
	// that is not itself a trusted proxy.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		hops := strings.Split(xff, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				continue
			}
			if !addrInAny(addr, trusted) {
				return addr.String()
			}
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-Ip")); xri != "" {
		if addr, err := netip.ParseAddr(xri); err == nil {
			return addr.String()
		}
	}
	return peer.String()
}

func peerAddr(remoteAddr string) (netip.Addr, bool) {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

func addrInAny(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Recover turns a handler panic into a logged 500 rather than a dropped
// connection, so one bad request cannot take down every live session in the
// process.
func Recover(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				// ErrAbortHandler is the documented way for a handler to drop a
				// connection deliberately; propagate it untouched.
				if rec == http.ErrAbortHandler { //nolint:errorlint // sentinel comparison is intended
					panic(rec)
				}
				log.ErrorContext(r.Context(), "panic recovered in handler",
					slog.Any("panic", rec),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("request_id", RequestID(r.Context())),
					slog.String("stack", string(debug.Stack())),
				)
				// If the handler already began a response, adding another
				// header would only produce a superfluous-write warning.
				if tracker, ok := w.(headerWriteTracker); ok && tracker.HeaderWritten() {
					return
				}
				Internal(w, r)
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// AccessLog records one line per request.
//
// Health checks log at debug: a container orchestrator polling every few
// seconds would otherwise bury everything else.
func AccessLog(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			// The ticket that authorises a WebSocket travels in the query
			// string, so the URI is scrubbed before it is recorded.
			uri := logging.ScrubString(r.URL.RequestURI())

			attrs := []any{
				slog.String("method", r.Method),
				slog.String("uri", uri),
				slog.Int("status", rec.status),
				slog.Int64("bytes", rec.bytes),
				slog.Duration("duration", time.Since(start).Round(time.Microsecond)),
				slog.String("client_ip", ClientIP(r.Context())),
				slog.String("request_id", RequestID(r.Context())),
			}
			if rec.hijacked {
				attrs = append(attrs, slog.Bool("hijacked", true))
			}

			ctx := r.Context()
			switch {
			case isHealthPath(r.URL.Path):
				log.DebugContext(ctx, "request", attrs...)
			case rec.status >= http.StatusInternalServerError:
				log.ErrorContext(ctx, "request", attrs...)
			case rec.status >= http.StatusBadRequest:
				log.WarnContext(ctx, "request", attrs...)
			default:
				log.InfoContext(ctx, "request", attrs...)
			}
		})
	}
}

func isHealthPath(p string) bool {
	switch p {
	case "/healthz", "/readyz", "/metrics":
		return true
	default:
		return false
	}
}

// SecurityHeaderOptions configures SecurityHeaders.
type SecurityHeaderOptions struct {
	// TLS enables HSTS. Sending HSTS over plain HTTP is ignored by browsers and
	// sending it from a development instance can poison the host for other
	// local services, so it is opt-in.
	TLS bool
	// CSP overrides the default policy. Empty uses DefaultCSP.
	CSP string
}

// DefaultCSP is the Content-Security-Policy served with the application.
//
// Notes on the two concessions, both deliberate and documented in
// docs/architecture/06-security.md:
//
//   - 'unsafe-inline' in style-src is required by Monaco, which injects styles
//     at runtime. It is not granted to script-src.
//   - 'wasm-unsafe-eval' covers xterm.js's WebGL renderer without permitting
//     JavaScript eval.
//
// There is no CDN host anywhere in the policy, which is both a security
// property and what makes air-gapped operation work.
const DefaultCSP = "default-src 'self'; " +
	"script-src 'self' 'wasm-unsafe-eval'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; " +
	"font-src 'self'; " +
	"connect-src 'self' ws: wss:; " +
	"worker-src 'self' blob:; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'; " +
	"object-src 'none'; " +
	"form-action 'self'"

// SecurityHeaders sets the response headers described in the security
// architecture on every response.
func SecurityHeaders(opts SecurityHeaderOptions) Middleware {
	csp := opts.CSP
	if csp == "" {
		csp = DefaultCSP
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), usb=(), payment=()")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			if opts.TLS {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			// API responses may carry inventory or session detail; keeping them
			// out of disk and proxy caches is cheap and avoids a class of leak.
			if strings.HasPrefix(r.URL.Path, "/api/") {
				h.Set("Cache-Control", "no-store")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Timeout bounds a request by cancelling its context.
//
// Deliberately not http.TimeoutHandler: that writes its own non-JSON response
// and is incompatible with hijacked connections, which rules it out for a
// server whose main job is long-lived WebSockets and streamed transfers.
// Cancelling the context instead lets each handler abort its database query or
// SSH request and return the standard error shape.
func Timeout(d time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// MaxBodyBytes caps the request body size.
func MaxBodyBytes(n int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if n > 0 && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// headerWriteTracker lets middleware ask whether a response has started.
type headerWriteTracker interface {
	HeaderWritten() bool
}

// responseRecorder captures the status and byte count for access logging while
// staying transparent to everything a handler might need from the underlying
// writer: flushing for streamed output, hijacking for WebSocket upgrades, and
// ReadFrom for efficient file downloads.
type responseRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
	hijacked    bool
}

func (rr *responseRecorder) WriteHeader(status int) {
	if rr.wroteHeader {
		return
	}
	rr.status = status
	rr.wroteHeader = true
	rr.ResponseWriter.WriteHeader(status)
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	if !rr.wroteHeader {
		rr.WriteHeader(http.StatusOK)
	}
	n, err := rr.ResponseWriter.Write(b)
	rr.bytes += int64(n)
	return n, err
}

// HeaderWritten implements headerWriteTracker.
func (rr *responseRecorder) HeaderWritten() bool { return rr.wroteHeader || rr.hijacked }

// Unwrap lets http.ResponseController reach the real writer, which is how
// modern WebSocket and streaming code obtains the underlying connection.
func (rr *responseRecorder) Unwrap() http.ResponseWriter { return rr.ResponseWriter }

func (rr *responseRecorder) Flush() {
	if f, ok := rr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rr *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := rr.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("httpx: underlying ResponseWriter does not support hijacking")
	}
	conn, buf, err := h.Hijack()
	if err == nil {
		rr.hijacked = true
	}
	return conn, buf, err
}

// ReadFrom preserves the zero-copy path used when streaming a download from an
// SFTP reader straight to the socket.
func (rr *responseRecorder) ReadFrom(src io.Reader) (int64, error) {
	if !rr.wroteHeader {
		rr.WriteHeader(http.StatusOK)
	}
	if rf, ok := rr.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(src)
		rr.bytes += n
		return n, err
	}
	n, err := io.Copy(rr.ResponseWriter, src)
	rr.bytes += n
	return n, err
}
