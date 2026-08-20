// Package api holds HTTP handlers. Handlers decode, delegate to a service, and
// encode; business logic lives in the module packages so it can be tested
// without an HTTP server.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/axt-term/axt-term/backend/internal/buildinfo"
	"github.com/axt-term/axt-term/backend/internal/httpx"
)

// readinessTimeout bounds the whole readiness probe. Orchestrators retry, so a
// probe that hangs is worse than one that fails fast.
const readinessTimeout = 3 * time.Second

// Check is one readiness dependency.
type Check struct {
	Name string
	// Critical failures make the instance not ready. Non-critical ones are
	// reported as degraded: a missing guacd means RDP is unavailable, not that
	// the whole workstation should be pulled out of service.
	Critical bool
	Probe    func(context.Context) error
}

// Health serves liveness, readiness, and version endpoints.
type Health struct {
	log    *slog.Logger
	mu     sync.RWMutex
	checks []Check
}

// NewHealth creates the handler.
func NewHealth(log *slog.Logger) *Health {
	return &Health{log: log}
}

// AddCheck registers a readiness dependency. Modules call this as they are
// wired, so readiness reflects whatever the build actually contains.
func (h *Health) AddCheck(c Check) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks = append(h.checks, c)
}

// Register adds the health routes to a router.
func (h *Health) Register(rt *httpx.Router) {
	rt.HandleFunc(httpx.Route{
		Method: http.MethodGet, Pattern: "/healthz", Access: httpx.AccessPublic,
		Summary: "Liveness probe",
	}, h.Live)

	rt.HandleFunc(httpx.Route{
		Method: http.MethodGet, Pattern: "/readyz", Access: httpx.AccessPublic,
		Summary: "Readiness probe including dependencies",
	}, h.Ready)

	rt.HandleFunc(httpx.Route{
		Method: http.MethodGet, Pattern: "/api/v1/version", Access: httpx.AccessPublic,
		Summary: "Build metadata",
	}, h.Version)
}

type liveResponse struct {
	Status string `json:"status"`
}

// Live reports that the process is running. It intentionally touches no
// dependency: a liveness probe that fails when the database is briefly busy
// causes an orchestrator to restart a healthy process and drop every live
// session with it.
func (h *Health) Live(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, liveResponse{Status: "ok"})
}

type checkResult struct {
	Status string `json:"status"` // ok, failed
	Error  string `json:"error,omitempty"`
	TookMS int64  `json:"took_ms"`
}

type readyResponse struct {
	Status  string                 `json:"status"` // ready, degraded, unavailable
	Version string                 `json:"version"`
	Checks  map[string]checkResult `json:"checks"`
}

// Ready reports whether the instance can serve traffic.
func (h *Health) Ready(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	checks := make([]Check, len(h.checks))
	copy(checks, h.checks)
	h.mu.RUnlock()

	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()

	results := make([]checkResult, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func(i int, c Check) {
			defer wg.Done()
			start := time.Now()
			res := checkResult{Status: "ok"}
			if err := c.Probe(ctx); err != nil {
				res.Status = "failed"
				res.Error = err.Error()
			}
			res.TookMS = time.Since(start).Milliseconds()
			results[i] = res
		}(i, c)
	}
	wg.Wait()

	resp := readyResponse{
		Status:  "ready",
		Version: buildinfo.Get().Version,
		Checks:  make(map[string]checkResult, len(checks)),
	}
	status := http.StatusOK
	for i, c := range checks {
		resp.Checks[c.Name] = results[i]
		if results[i].Status == "ok" {
			continue
		}
		if c.Critical {
			resp.Status = "unavailable"
			status = http.StatusServiceUnavailable
		} else if resp.Status == "ready" {
			resp.Status = "degraded"
		}
	}

	if status != http.StatusOK {
		h.log.WarnContext(ctx, "readiness probe failed", slog.Any("checks", resp.Checks))
	}
	httpx.WriteJSON(w, status, resp)
}

// Version returns build metadata.
func (h *Health) Version(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, buildinfo.Get())
}
