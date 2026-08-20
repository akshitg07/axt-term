package httpx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/axt-term/axt-term/backend/internal/logging"
)

func okHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"ok": "yes"})
	}
}

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

// The central security property of the router: a route that forgets to declare
// how it is protected must fail startup rather than serve unprotected.
func TestValidateRejectsUndeclaredAccess(t *testing.T) {
	t.Parallel()

	rt := NewRouter()
	rt.HandleFunc(Route{Method: http.MethodGet, Pattern: "/api/v1/hosts"}, okHandler())

	err := rt.Validate(nil)
	if err == nil {
		t.Fatal("a route with no Access declaration must be rejected")
	}
	if !strings.Contains(err.Error(), "/api/v1/hosts") || !strings.Contains(err.Error(), "no Access declared") {
		t.Errorf("error should name the route and the problem: %v", err)
	}
}

func TestValidatePermissionRules(t *testing.T) {
	t.Parallel()

	t.Run("permission access needs a permission", func(t *testing.T) {
		rt := NewRouter()
		rt.HandleFunc(Route{Method: http.MethodPost, Pattern: "/api/v1/hosts", Access: AccessPermission}, okHandler())
		err := rt.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "Permission is empty") {
			t.Fatalf("expected an empty-permission error, got: %v", err)
		}
	})

	t.Run("public access must not carry a permission", func(t *testing.T) {
		rt := NewRouter()
		rt.HandleFunc(Route{
			Method: http.MethodGet, Pattern: "/healthz",
			Access: AccessPublic, Permission: "host.read",
		}, okHandler())
		err := rt.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "host.read") {
			t.Fatalf("expected a stray-permission error, got: %v", err)
		}
	})

	t.Run("unknown permission is rejected when a registry is supplied", func(t *testing.T) {
		rt := NewRouter()
		rt.HandleFunc(Route{
			Method: http.MethodGet, Pattern: "/api/v1/audit",
			Access: AccessPermission, Permission: "admin.audti", // typo
		}, okHandler())
		known := func(p string) bool { return p == "admin.audit" }
		err := rt.Validate(known)
		if err == nil || !strings.Contains(err.Error(), "unknown permission") {
			t.Fatalf("expected an unknown-permission error, got: %v", err)
		}
	})

	t.Run("valid table passes", func(t *testing.T) {
		rt := NewRouter()
		rt.HandleFunc(Route{Method: http.MethodGet, Pattern: "/healthz", Access: AccessPublic}, okHandler())
		rt.HandleFunc(Route{Method: http.MethodGet, Pattern: "/api/v1/auth/me", Access: AccessAuthenticated}, okHandler())
		rt.HandleFunc(Route{
			Method: http.MethodPost, Pattern: "/api/v1/hosts",
			Access: AccessPermission, Permission: "host.write",
		}, okHandler())
		known := func(p string) bool { return p == "host.write" }
		if err := rt.Validate(known); err != nil {
			t.Fatalf("valid table should pass: %v", err)
		}
	})
}

func TestValidateRejectsDuplicateRoutes(t *testing.T) {
	t.Parallel()

	rt := NewRouter()
	route := Route{Method: http.MethodGet, Pattern: "/api/v1/hosts", Access: AccessAuthenticated}
	rt.HandleFunc(route, okHandler())
	rt.HandleFunc(route, okHandler())

	err := rt.Validate(nil)
	if err == nil || !strings.Contains(err.Error(), "duplicate route") {
		t.Fatalf("expected a duplicate-route error, got: %v", err)
	}
}

func TestMethodNotAllowedIsJSONWithAllowHeader(t *testing.T) {
	t.Parallel()

	rt := NewRouter()
	rt.HandleFunc(Route{Method: http.MethodGet, Pattern: "/api/v1/hosts", Access: AccessAuthenticated}, okHandler())
	rt.HandleFunc(Route{Method: http.MethodPost, Pattern: "/api/v1/hosts", Access: AccessAuthenticated}, okHandler())
	if err := rt.Validate(nil); err != nil {
		t.Fatal(err)
	}
	srv := rt.Handler()

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/hosts", nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	allow := rec.Header().Get("Allow")
	for _, want := range []string{"GET", "POST", "HEAD", "OPTIONS"} {
		if !strings.Contains(allow, want) {
			t.Errorf("Allow header %q is missing %s", allow, want)
		}
	}
	var body errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("405 body must be our JSON shape, got %q: %v", rec.Body.String(), err)
	}
	if body.Error.Code != CodeMethodNotAllowed {
		t.Errorf("code = %q", body.Error.Code)
	}
}

func TestOptionsAndHeadHandling(t *testing.T) {
	t.Parallel()

	rt := NewRouter()
	rt.HandleFunc(Route{Method: http.MethodGet, Pattern: "/api/v1/version", Access: AccessPublic}, okHandler())
	if err := rt.Validate(nil); err != nil {
		t.Fatal(err)
	}
	srv := rt.Handler()

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/api/v1/version", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("OPTIONS status = %d, want 204", rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/api/v1/version", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("HEAD status = %d, want 200 via the GET handler", rec.Code)
	}
}

func TestNotFoundIsJSON(t *testing.T) {
	t.Parallel()

	rt := NewRouter()
	rt.HandleFunc(Route{Method: http.MethodGet, Pattern: "/healthz", Access: AccessPublic}, okHandler())
	if err := rt.Validate(nil); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	rt.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var body errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("404 body must be JSON, got %q", rec.Body.String())
	}
	if body.Error.Code != CodeNotFound {
		t.Errorf("code = %q", body.Error.Code)
	}
}

func TestRecoverReturnsOpaque500AndLogsDetail(t *testing.T) {
	t.Parallel()

	var logBuf bytes.Buffer
	log, err := logging.New(logging.Options{Level: "debug", Format: "json", Output: &logBuf})
	if err != nil {
		t.Fatal(err)
	}

	panicky := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("internal detail: /etc/axt/master.key unreadable")
	})
	h := Chain(panicky, AssignRequestID, AccessLog(log), Recover(log))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "master.key") {
		t.Errorf("panic detail leaked to the client: %s", rec.Body.String())
	}
	var body errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("500 body must be JSON: %v", err)
	}
	if body.Error.RequestID == "" {
		t.Error("a 500 must carry the request id so the log line can be found")
	}
	if !strings.Contains(logBuf.String(), "master.key") {
		t.Error("the panic detail must reach the log even though it is withheld from the client")
	}
	if !strings.Contains(logBuf.String(), "panic recovered") {
		t.Error("panic should be logged")
	}
}

// A handler that has already started writing must not have a second header
// written over it.
func TestRecoverAfterPartialResponse(t *testing.T) {
	t.Parallel()

	log := logging.Discard()
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"partial":true`))
		panic("late failure")
	}), AccessLog(log), Recover(log))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; the already-sent 200 must stand", rec.Code)
	}
	if strings.Contains(rec.Body.String(), CodeInternal) {
		t.Errorf("no error envelope should be appended to a started response: %s", rec.Body.String())
	}
}

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()

	t.Run("api response over tls", func(t *testing.T) {
		h := Chain(okHandler(), SecurityHeaders(SecurityHeaderOptions{TLS: true}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil))

		want := map[string]string{
			"Content-Security-Policy":      DefaultCSP,
			"X-Content-Type-Options":       "nosniff",
			"X-Frame-Options":              "DENY",
			"Referrer-Policy":              "no-referrer",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cross-Origin-Resource-Policy": "same-origin",
			"Strict-Transport-Security":    "max-age=31536000; includeSubDomains",
			"Cache-Control":                "no-store",
		}
		for k, v := range want {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s = %q, want %q", k, got, v)
			}
		}
	})

	t.Run("no hsts without tls", func(t *testing.T) {
		h := Chain(okHandler(), SecurityHeaders(SecurityHeaderOptions{TLS: false}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil))
		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("HSTS must not be sent over plain HTTP, got %q", got)
		}
	})

	t.Run("no-store only on api paths", func(t *testing.T) {
		h := Chain(okHandler(), SecurityHeaders(SecurityHeaderOptions{}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
		if got := rec.Header().Get("Cache-Control"); got == "no-store" {
			t.Error("static assets must stay cacheable")
		}
	})

	t.Run("csp forbids cdn and inline script", func(t *testing.T) {
		if strings.Contains(DefaultCSP, "unsafe-inline'; script") {
			t.Error("script-src must not allow unsafe-inline")
		}
		if strings.Contains(DefaultCSP, "http://") || strings.Contains(DefaultCSP, "https://") {
			t.Error("CSP must not reference an external host; air-gapped operation depends on it")
		}
		if !strings.Contains(DefaultCSP, "frame-ancestors 'none'") {
			t.Error("CSP must forbid framing")
		}
	})
}

func TestResolveClientIP(t *testing.T) {
	t.Parallel()

	trusted := mustPrefixes(t, "10.0.0.0/8", "172.18.0.0/16")

	for _, tc := range []struct {
		name    string
		remote  string
		xff     string
		xri     string
		trusted []netip.Prefix
		want    string
	}{
		{
			name:   "no proxies configured means the header is ignored",
			remote: "203.0.113.9:5555",
			xff:    "1.2.3.4",
			want:   "203.0.113.9",
		},
		{
			name:    "untrusted peer cannot forge the header",
			remote:  "203.0.113.9:5555",
			xff:     "1.2.3.4",
			trusted: trusted,
			want:    "203.0.113.9",
		},
		{
			name:    "trusted proxy reveals the client",
			remote:  "10.0.0.5:4444",
			xff:     "198.51.100.7",
			trusted: trusted,
			want:    "198.51.100.7",
		},
		{
			name:    "chain of trusted proxies resolves to the outermost client",
			remote:  "10.0.0.5:4444",
			xff:     "198.51.100.7, 172.18.0.3, 10.0.0.9",
			trusted: trusted,
			want:    "198.51.100.7",
		},
		{
			name:    "client-supplied spoof ahead of the real address is not selected",
			remote:  "10.0.0.5:4444",
			xff:     "9.9.9.9, 198.51.100.7",
			trusted: trusted,
			want:    "198.51.100.7",
		},
		{
			name:    "x-real-ip is used when no forwarded chain exists",
			remote:  "10.0.0.5:4444",
			xri:     "198.51.100.20",
			trusted: trusted,
			want:    "198.51.100.20",
		},
		{
			name:    "garbage header falls back to the peer",
			remote:  "10.0.0.5:4444",
			xff:     "not-an-ip",
			trusted: trusted,
			want:    "10.0.0.5",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xri != "" {
				r.Header.Set("X-Real-Ip", tc.xri)
			}
			if got := resolveClientIP(r, tc.trusted); got != tc.want {
				t.Errorf("resolveClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAssignRequestID(t *testing.T) {
	t.Parallel()

	var seen string
	h := AssignRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
	}))

	t.Run("generates when absent", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if seen == "" {
			t.Fatal("no request id in context")
		}
		if rec.Header().Get(RequestIDHeader) != seen {
			t.Error("the response header must echo the context value")
		}
	})

	t.Run("honours a well-formed inbound id", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(RequestIDHeader, "proxy-assigned-1234")
		h.ServeHTTP(httptest.NewRecorder(), r)
		if seen != "proxy-assigned-1234" {
			t.Errorf("request id = %q, want the inbound value", seen)
		}
	})

	t.Run("rejects an id that could corrupt a log line", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(RequestIDHeader, "bad\nid with spaces")
		h.ServeHTTP(httptest.NewRecorder(), r)
		if strings.ContainsAny(seen, " \n") {
			t.Errorf("request id = %q; control characters must be rejected", seen)
		}
	})
}

// A WebSocket ticket travels in the query string, so it must not survive into
// the access log.
func TestAccessLogScrubsTicketFromURI(t *testing.T) {
	t.Parallel()

	var logBuf bytes.Buffer
	log, err := logging.New(logging.Options{Level: "debug", Format: "json", Output: &logBuf})
	if err != nil {
		t.Fatal(err)
	}
	h := Chain(okHandler(), AccessLog(log))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ws/terminal?session=s1&ticket=super-secret-ticket", nil))

	out := logBuf.String()
	if strings.Contains(out, "super-secret-ticket") {
		t.Fatalf("ticket leaked into the access log:\n%s", out)
	}
	if !strings.Contains(out, "/ws/terminal") {
		t.Errorf("the path must still be logged:\n%s", out)
	}
}

func TestAccessLogLevels(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		status int
		path   string
		want   string
	}{
		{http.StatusOK, "/api/v1/hosts", `"level":"INFO"`},
		{http.StatusNotFound, "/api/v1/hosts", `"level":"WARN"`},
		{http.StatusInternalServerError, "/api/v1/hosts", `"level":"ERROR"`},
		{http.StatusOK, "/healthz", `"level":"DEBUG"`},
	} {
		var buf bytes.Buffer
		log, err := logging.New(logging.Options{Level: "debug", Format: "json", Output: &buf})
		if err != nil {
			t.Fatal(err)
		}
		status := tc.status
		h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}), AccessLog(log))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.path, nil))

		if !strings.Contains(buf.String(), tc.want) {
			t.Errorf("status %d on %s: expected %s in:\n%s", tc.status, tc.path, tc.want, buf.String())
		}
	}
}

func TestDecodeJSON(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `json:"name"`
		Port int    `json:"port"`
	}

	decode := func(body, contentType string, maxBytes int64) (*httptest.ResponseRecorder, payload, error) {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", strings.NewReader(body))
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		rec := httptest.NewRecorder()
		var dst payload
		err := DecodeJSON(rec, r, &dst, maxBytes)
		return rec, dst, err
	}

	t.Run("valid", func(t *testing.T) {
		_, got, err := decode(`{"name":"web01","port":22}`, "application/json", 0)
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != "web01" || got.Port != 22 {
			t.Errorf("decoded %+v", got)
		}
	})

	// Silently ignoring a misspelled field means a user believes they changed a
	// setting that was never applied.
	t.Run("unknown field is rejected", func(t *testing.T) {
		rec, _, err := decode(`{"name":"web01","prot":22}`, "application/json", 0)
		if err == nil {
			t.Fatal("expected an error")
		}
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "prot") {
			t.Errorf("the response should name the offending field: %s", rec.Body.String())
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		rec, _, err := decode(`{"port":"twenty-two"}`, "application/json", 0)
		if err == nil {
			t.Fatal("expected an error")
		}
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422", rec.Code)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		rec, _, err := decode(`{"name":`, "application/json", 0)
		if err == nil {
			t.Fatal("expected an error")
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("empty body", func(t *testing.T) {
		rec, _, err := decode(``, "application/json", 0)
		if err == nil {
			t.Fatal("expected an error")
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("too large", func(t *testing.T) {
		rec, _, err := decode(`{"name":"`+strings.Repeat("a", 500)+`"}`, "application/json", 64)
		if err == nil {
			t.Fatal("expected an error")
		}
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413", rec.Code)
		}
	})

	t.Run("wrong content type", func(t *testing.T) {
		rec, _, err := decode(`{"name":"x"}`, "text/plain", 0)
		if err == nil {
			t.Fatal("expected an error")
		}
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("status = %d, want 415", rec.Code)
		}
	})

	t.Run("trailing value", func(t *testing.T) {
		rec, _, err := decode(`{"name":"a"}{"name":"b"}`, "application/json", 0)
		if err == nil {
			t.Fatal("expected an error")
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}

func TestChainOrder(t *testing.T) {
	t.Parallel()

	var order []string
	mark := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		order = append(order, "handler")
	}), mark("outer"), mark("inner"))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"outer", "inner", "handler"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", order, want)
	}
}

func TestNotImplementedIsHonest(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	NotImplemented(rec, httptest.NewRequest(http.MethodGet, "/api/v1/tunnels", nil), "SSH tunnels", "phase-2")

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
	var body errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Details["phase"] != "phase-2" {
		t.Errorf("the phase must be reported so the UI can say when: %+v", body.Error.Details)
	}
}

func TestWriteJSONSetsHeaders(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusCreated, map[string]int{"n": 1})

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff must be set on JSON responses")
	}
}

// An unencodable value must not produce a 200 with a truncated body.
func TestWriteJSONHandlesEncodeFailure(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusOK, map[string]any{"bad": func() {}})

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestServerConfigDefaultsAvoidBreakingWebSockets(t *testing.T) {
	t.Parallel()

	srv := NewServer(ServerConfig{Addr: "127.0.0.1:0"}, okHandler(), slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	// A connection-wide read or write deadline would kill every long-lived
	// terminal session and every large transfer on a fixed schedule.
	if srv.srv.ReadTimeout != 0 {
		t.Errorf("ReadTimeout must stay unset, got %s", srv.srv.ReadTimeout)
	}
	if srv.srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout must stay unset, got %s", srv.srv.WriteTimeout)
	}
	if srv.srv.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout should be set to bound slow-header clients")
	}
}
