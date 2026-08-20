package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/axt-term/axt-term/backend/internal/httpx"
	"github.com/axt-term/axt-term/backend/internal/logging"
)

func TestLiveIgnoresDependencies(t *testing.T) {
	t.Parallel()

	h := NewHealth(logging.Discard())
	// A liveness probe that fails when the database is briefly busy causes an
	// orchestrator to restart a healthy process and drop every live session.
	h.AddCheck(Check{Name: "database", Critical: true, Probe: func(context.Context) error {
		return errors.New("database is down")
	}})

	rec := httptest.NewRecorder()
	h.Live(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 regardless of dependencies", rec.Code)
	}
}

func TestReadyReflectsDependencies(t *testing.T) {
	t.Parallel()

	t.Run("all healthy", func(t *testing.T) {
		h := NewHealth(logging.Discard())
		h.AddCheck(Check{Name: "database", Critical: true, Probe: func(context.Context) error { return nil }})
		h.AddCheck(Check{Name: "guacd", Probe: func(context.Context) error { return nil }})

		rec := httptest.NewRecorder()
		h.Ready(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var body readyResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Status != "ready" {
			t.Errorf("status = %q, want ready", body.Status)
		}
		if len(body.Checks) != 2 {
			t.Errorf("checks = %+v", body.Checks)
		}
	})

	t.Run("critical failure is unavailable", func(t *testing.T) {
		h := NewHealth(logging.Discard())
		h.AddCheck(Check{Name: "database", Critical: true, Probe: func(context.Context) error {
			return errors.New("disk I/O error")
		}})

		rec := httptest.NewRecorder()
		h.Ready(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
		var body readyResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Status != "unavailable" {
			t.Errorf("status = %q", body.Status)
		}
		if body.Checks["database"].Error == "" {
			t.Error("the failing check should report why")
		}
	})

	// A missing guacd means RDP is unavailable, not that the whole workstation
	// should be pulled out of service.
	t.Run("non-critical failure is degraded but still serving", func(t *testing.T) {
		h := NewHealth(logging.Discard())
		h.AddCheck(Check{Name: "database", Critical: true, Probe: func(context.Context) error { return nil }})
		h.AddCheck(Check{Name: "guacd", Probe: func(context.Context) error {
			return errors.New("connection refused")
		}})

		rec := httptest.NewRecorder()
		h.Ready(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var body readyResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Status != "degraded" {
			t.Errorf("status = %q, want degraded", body.Status)
		}
	})
}

func TestHealthRoutesAreRegisteredAsPublic(t *testing.T) {
	t.Parallel()

	rt := httpx.NewRouter()
	NewHealth(logging.Discard()).Register(rt)

	if err := rt.Validate(nil); err != nil {
		t.Fatalf("health routes must be a valid table: %v", err)
	}

	want := map[string]bool{
		"GET /healthz":          false,
		"GET /readyz":           false,
		"GET /api/v1/version":   false,
	}
	for _, r := range rt.Routes() {
		key := r.Method + " " + r.Pattern
		if _, ok := want[key]; !ok {
			t.Errorf("unexpected route %s", key)
			continue
		}
		want[key] = true
		if r.Access != httpx.AccessPublic {
			t.Errorf("%s access = %s, want public: probes run before authentication exists", key, r.Access)
		}
	}
	for key, seen := range want {
		if !seen {
			t.Errorf("%s was not registered", key)
		}
	}
}

func TestVersionReportsBuildInfo(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	NewHealth(logging.Discard()).Version(rec, httptest.NewRequest(http.MethodGet, "/api/v1/version", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"version", "go_version", "platform"} {
		if body[field] == nil || body[field] == "" {
			t.Errorf("%s is missing from %v", field, body)
		}
	}
}
