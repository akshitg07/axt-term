package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/axt-term/axt-term/backend/internal/auth"
	"github.com/axt-term/axt-term/backend/internal/config"
	"github.com/axt-term/axt-term/backend/internal/credentials"
	"github.com/axt-term/axt-term/backend/internal/events"
	"github.com/axt-term/axt-term/backend/internal/httpx"
	"github.com/axt-term/axt-term/backend/internal/inventory"
	"github.com/axt-term/axt-term/backend/internal/rbac"
	"github.com/axt-term/axt-term/backend/internal/rdp"
	"github.com/axt-term/axt-term/backend/internal/sshx"
	"github.com/axt-term/axt-term/backend/internal/store"
	"github.com/axt-term/axt-term/backend/internal/terminal"
	"github.com/axt-term/axt-term/backend/internal/validate"
)

// Server holds the dependencies every handler needs.
type Server struct {
	cfg         *config.Config
	store       *store.Store
	auth        *auth.Service
	creds       *credentials.Service
	inventory   *inventory.Service
	sessions    *terminal.Registry
	bridge      *terminal.Bridge
	desktops    *rdp.Registry
	rdpBridge   *rdp.Bridge
	pool        *sshx.Pool
	bus         *events.Bus
	audit       *Auditor
	health      *Health
	pendingKeys *pendingHostKeyStore
	log         *slog.Logger
}

// Deps is the constructor argument, kept as a struct so adding a dependency does
// not churn every call site.
type Deps struct {
	Config    *config.Config
	Store     *store.Store
	Auth      *auth.Service
	Creds     *credentials.Service
	Inventory *inventory.Service
	Sessions  *terminal.Registry
	Bridge    *terminal.Bridge
	Desktops  *rdp.Registry
	RDPBridge *rdp.Bridge
	Pool      *sshx.Pool
	Bus       *events.Bus
	Log       *slog.Logger
}

// New creates the API server.
func New(d Deps) *Server {
	return &Server{
		cfg:         d.Config,
		store:       d.Store,
		auth:        d.Auth,
		creds:       d.Creds,
		inventory:   d.Inventory,
		sessions:    d.Sessions,
		bridge:      d.Bridge,
		desktops:    d.Desktops,
		rdpBridge:   d.RDPBridge,
		pool:        d.Pool,
		bus:         d.Bus,
		audit:       NewAuditor(d.Store, d.Log),
		health:      NewHealth(d.Log),
		pendingKeys: newPendingHostKeyStore(),
		log:         d.Log,
	}
}

// HealthHandler exposes the health handler so readiness checks can be registered.
func (s *Server) HealthHandler() *Health { return s.health }

// maxBody bounds a configuration payload. File uploads use their own streaming
// path and are not subject to this.
const maxBody = 1 << 20

// Register adds every route to the router.
//
// The route table is the security-relevant surface of the application, so it is
// written in one place where it can be read end to end. Every entry declares its
// protection, and httpx.Router.Validate refuses to start the server if any entry
// omits it or names a permission the RBAC registry does not know.
func (s *Server) Register(rt *httpx.Router) {
	s.health.Register(rt)

	pub := func(method, pattern string, h http.HandlerFunc) {
		rt.HandleFunc(httpx.Route{Method: method, Pattern: pattern, Access: httpx.AccessPublic}, h)
	}
	authed := func(method, pattern string, h http.HandlerFunc) {
		rt.HandleFunc(httpx.Route{Method: method, Pattern: pattern, Access: httpx.AccessAuthenticated}, h)
	}
	perm := func(method, pattern, permission string, h http.HandlerFunc) {
		rt.HandleFunc(httpx.Route{
			Method: method, Pattern: pattern,
			Access: httpx.AccessPermission, Permission: permission,
		}, h)
	}
	stream := func(method, pattern, permission string, h http.HandlerFunc) {
		rt.HandleFunc(httpx.Route{
			Method: method, Pattern: pattern,
			Access: httpx.AccessPermission, Permission: permission, Streaming: true,
		}, h)
	}

	// --- authentication --------------------------------------------------
	pub(http.MethodPost, "/api/v1/auth/login", s.handleLogin)
	authed(http.MethodPost, "/api/v1/auth/logout", s.handleLogout)
	authed(http.MethodGet, "/api/v1/auth/me", s.handleMe)
	authed(http.MethodPost, "/api/v1/auth/password", s.handleChangePassword)
	authed(http.MethodGet, "/api/v1/auth/sessions", s.handleListAuthSessions)
	authed(http.MethodDelete, "/api/v1/auth/sessions/{id}", s.handleRevokeAuthSession)

	// --- inventory -------------------------------------------------------
	perm(http.MethodGet, "/api/v1/folders", rbac.HostRead, s.handleListFolders)
	perm(http.MethodPost, "/api/v1/folders", rbac.HostWrite, s.handleCreateFolder)
	perm(http.MethodPatch, "/api/v1/folders/{id}", rbac.HostWrite, s.handleUpdateFolder)
	perm(http.MethodDelete, "/api/v1/folders/{id}", rbac.HostWrite, s.handleDeleteFolder)
	perm(http.MethodPost, "/api/v1/folders/{id}/move", rbac.HostWrite, s.handleMoveFolder)

	perm(http.MethodGet, "/api/v1/hosts", rbac.HostRead, s.handleListHosts)
	perm(http.MethodPost, "/api/v1/hosts", rbac.HostWrite, s.handleCreateHost)
	perm(http.MethodGet, "/api/v1/hosts/{id}", rbac.HostRead, s.handleGetHost)
	perm(http.MethodPatch, "/api/v1/hosts/{id}", rbac.HostWrite, s.handleUpdateHost)
	perm(http.MethodDelete, "/api/v1/hosts/{id}", rbac.HostWrite, s.handleDeleteHost)
	perm(http.MethodPost, "/api/v1/hosts/{id}/favorite", rbac.HostWrite, s.handleFavoriteHost)
	perm(http.MethodPost, "/api/v1/hosts/{id}/duplicate", rbac.HostWrite, s.handleDuplicateHost)
	perm(http.MethodPost, "/api/v1/hosts/{id}/test", rbac.HostRead, s.handleTestHost)
	perm(http.MethodGet, "/api/v1/hosts/{id}/actions", rbac.HostRead, s.handleHostActions)

	perm(http.MethodGet, "/api/v1/tags", rbac.HostRead, s.handleListTags)
	perm(http.MethodPost, "/api/v1/tags", rbac.HostWrite, s.handleCreateTag)
	perm(http.MethodDelete, "/api/v1/tags/{id}", rbac.HostWrite, s.handleDeleteTag)

	perm(http.MethodGet, "/api/v1/host-keys", rbac.HostRead, s.handleListHostKeys)
	perm(http.MethodPost, "/api/v1/host-keys/trust", rbac.HostWrite, s.handleTrustHostKey)
	perm(http.MethodDelete, "/api/v1/host-keys/{id}", rbac.AdminHostKeys, s.handleRevokeHostKey)

	// --- credentials -----------------------------------------------------
	perm(http.MethodGet, "/api/v1/credentials", rbac.CredentialRead, s.handleListCredentials)
	perm(http.MethodPost, "/api/v1/credentials", rbac.CredentialWrite, s.handleCreateCredential)
	perm(http.MethodGet, "/api/v1/credentials/{id}", rbac.CredentialRead, s.handleGetCredential)
	perm(http.MethodPatch, "/api/v1/credentials/{id}", rbac.CredentialWrite, s.handleUpdateCredential)
	perm(http.MethodDelete, "/api/v1/credentials/{id}", rbac.CredentialWrite, s.handleDeleteCredential)

	// --- sessions --------------------------------------------------------
	perm(http.MethodPost, "/api/v1/sessions", rbac.SessionSSH, s.handleCreateSession)
	perm(http.MethodGet, "/api/v1/sessions", rbac.SessionSSH, s.handleListSessions)
	perm(http.MethodGet, "/api/v1/sessions/{id}", rbac.SessionSSH, s.handleGetSession)
	perm(http.MethodDelete, "/api/v1/sessions/{id}", rbac.SessionSSH, s.handleCloseSession)
	perm(http.MethodPost, "/api/v1/sessions/{id}/ticket", rbac.SessionSSH, s.handleSessionTicket)
	perm(http.MethodPost, "/api/v1/sessions/{id}/resize", rbac.SessionSSH, s.handleResizeSession)
	perm(http.MethodPost, "/api/v1/sessions/{id}/recording", rbac.SessionRecord, s.handleSessionRecording)
	perm(http.MethodGet, "/api/v1/sessions/recent", rbac.SessionSSH, s.handleRecentSessions)
	// Curating history. A literal segment does win over {id} at the same depth,
	// which is why GET /sessions/recent coexists with GET /sessions/{id} -- but
	// that only holds while the literal is the *last* segment. Per-record deletion
	// therefore lives outside the /sessions/ subtree entirely: any
	// /sessions/<literal>/{id} pattern overlaps /sessions/{id}/<literal> on paths
	// like /sessions/recent/ticket, ServeMux considers neither more specific, and
	// it panics at registration -- taking the process down on every start rather
	// than failing a request. The id here is a history record's, not a live
	// session's, so the separate path is honest about naming a different resource.
	perm(http.MethodDelete, "/api/v1/sessions/recent", rbac.SessionSSH, s.handleClearRecentSessions)
	perm(http.MethodDelete, "/api/v1/recent-sessions/{id}", rbac.SessionSSH, s.handleDeleteRecentSession)
	perm(http.MethodPost, "/api/v1/events/ticket", rbac.HostRead, s.handleEventsTicket)

	// WebSockets are streaming routes: no request timeout, no body limit.
	// They authenticate with a single-use ticket rather than the session cookie,
	// so they are registered as public and enforce their own check.
	rt.HandleFunc(httpx.Route{
		Method: http.MethodGet, Pattern: "/ws/terminal",
		Access: httpx.AccessPublic, Streaming: true,
		Summary: "Terminal I/O; authenticated by single-use ticket",
	}, s.bridge.ServeTerminal)
	rt.HandleFunc(httpx.Route{
		Method: http.MethodGet, Pattern: "/ws/rdp",
		Access: httpx.AccessPublic, Streaming: true,
		Summary: "Guacamole instruction stream for RDP and VNC; authenticated by single-use ticket",
	}, s.rdpBridge.ServeRDP)
	rt.HandleFunc(httpx.Route{
		Method: http.MethodGet, Pattern: "/ws/events",
		Access: httpx.AccessPublic, Streaming: true,
		Summary: "Notification stream; authenticated by single-use ticket",
	}, s.bridge.ServeEvents)

	// --- snippets --------------------------------------------------------
	perm(http.MethodGet, "/api/v1/snippets", rbac.SnippetRead, s.handleListSnippets)
	perm(http.MethodPost, "/api/v1/snippets", rbac.SnippetWrite, s.handleCreateSnippet)
	perm(http.MethodPatch, "/api/v1/snippets/{id}", rbac.SnippetWrite, s.handleUpdateSnippet)
	perm(http.MethodDelete, "/api/v1/snippets/{id}", rbac.SnippetWrite, s.handleDeleteSnippet)
	perm(http.MethodPost, "/api/v1/snippets/{id}/render", rbac.SnippetRead, s.handleRenderSnippet)
	perm(http.MethodGet, "/api/v1/snippet-folders", rbac.SnippetRead, s.handleListSnippetFolders)

	// --- search, settings, audit ----------------------------------------
	authed(http.MethodGet, "/api/v1/search", s.handleSearch)
	authed(http.MethodGet, "/api/v1/me/settings", s.handleGetUserSettings)
	authed(http.MethodPut, "/api/v1/me/settings", s.handleSetUserSettings)
	perm(http.MethodGet, "/api/v1/settings", rbac.AdminSettings, s.handleGetSettings)
	perm(http.MethodPut, "/api/v1/settings", rbac.AdminSettings, s.handleSetSettings)
	perm(http.MethodGet, "/api/v1/audit", rbac.AdminAudit, s.handleListAudit)
	perm(http.MethodGet, "/api/v1/audit/actions", rbac.AdminAudit, s.handleAuditActions)

	// --- transfers (queue surface; the SFTP engine lands in M9) ---------
	perm(http.MethodGet, "/api/v1/transfers", rbac.FileRead, s.handleListTransfers)
	perm(http.MethodPost, "/api/v1/transfers/{id}/retry", rbac.FileWrite, s.handleRetryTransfer)
	perm(http.MethodDelete, "/api/v1/transfers/{id}", rbac.FileWrite, s.handleDeleteTransfer)

	// --- not yet implemented, declared so the UI can label them ---------
	// Each returns 501 with its phase, which is how a Coming Soon panel knows
	// what to say instead of showing a generic failure.
	comingSoon := func(method, pattern, permission, feature, phase string) {
		perm(method, pattern, permission, func(w http.ResponseWriter, r *http.Request) {
			httpx.NotImplemented(w, r, feature, phase)
		})
	}
	comingSoon(http.MethodGet, "/api/v1/hosts/{id}/processes", rbac.ServiceRead, "Process manager", "phase-2")
	comingSoon(http.MethodGet, "/api/v1/hosts/{id}/services", rbac.ServiceRead, "Service manager", "phase-2")
	comingSoon(http.MethodPost, "/api/v1/exec/batch", rbac.ExecBatch, "Command Center", "phase-2")
	comingSoon(http.MethodGet, "/api/v1/tunnels", rbac.TunnelRead, "SSH tunnels", "phase-2")
	comingSoon(http.MethodGet, "/api/v1/hosts/{id}/docker/containers", rbac.DockerRead, "Docker manager", "phase-3")
	comingSoon(http.MethodGet, "/api/v1/clusters", rbac.KubeRead, "Kubernetes manager", "phase-3")

	_ = stream // reserved for the SFTP download and upload routes in M9
}

// ------------------------------------------------------------ shared helpers ---

// principal returns the authenticated identity. Routes reaching a handler are
// always authenticated unless declared public, so a nil here is a wiring bug.
func (s *Server) principal(r *http.Request) *auth.Principal {
	return auth.PrincipalFrom(r.Context())
}

// fail maps a service error onto the standard error envelope.
//
// One place, so a new handler cannot invent a different status for the same
// condition.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var verrs *validate.Errors
	switch {
	case errors.As(err, &verrs):
		httpx.ValidationFailed(w, r, verrs.Map())
	case errors.Is(err, store.ErrNotFound), errors.Is(err, terminal.ErrNotFound),
		errors.Is(err, rdp.ErrNotFound):
		httpx.NotFound(w, r, "resource")
	case errors.Is(err, store.ErrConflict):
		httpx.Conflict(w, r, err.Error())
	case errors.Is(err, store.ErrInUse), errors.Is(err, credentials.ErrInUse):
		httpx.Conflict(w, r, err.Error())
	case errors.Is(err, terminal.ErrSessionLimit), errors.Is(err, rdp.ErrLimit):
		httpx.WriteError(w, r, http.StatusTooManyRequests, httpx.CodeRateLimited, err.Error())
	case errors.Is(err, terminal.ErrUnsupported), errors.Is(err, credentials.ErrProviderUnsupported),
		errors.Is(err, inventory.ErrPromptedAuthUnavailable),
		errors.Is(err, rdp.ErrUnsupported), errors.Is(err, rdp.ErrDisabled):
		httpx.WriteError(w, r, http.StatusNotImplemented, httpx.CodeNotImplemented, err.Error())
	case errors.Is(err, rdp.ErrUnavailable):
		// The gateway, not the target. Distinguished so the message does not send
		// somebody checking a Windows host that is perfectly healthy.
		httpx.WriteErrorDetails(w, r, http.StatusServiceUnavailable, httpx.CodeUnavailable,
			err.Error(), map[string]any{"setting": "AXT_GUACD_ADDR"})
	case errors.Is(err, rdp.ErrRemote), errors.Is(err, rdp.ErrHandshake):
		httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeUpstreamFailure, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		httpx.WriteError(w, r, http.StatusGatewayTimeout, httpx.CodeUpstreamTimeout,
			"the target host did not respond in time")
	default:
		s.log.ErrorContext(r.Context(), "request failed", slog.Any("error", err))
		httpx.Internal(w, r)
	}
}

// decode reads a JSON body, writing the error response itself on failure.
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	return httpx.DecodeJSON(w, r, dst, maxBody) == nil
}

// queryBool reads an optional boolean query parameter.
func queryBool(r *http.Request, name string) bool {
	switch r.URL.Query().Get(name) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// queryInt reads an optional integer query parameter.
func queryInt(r *http.Request, name string, def int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	n := 0
	for _, c := range raw {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000 {
			return def
		}
	}
	return n
}

// listEnvelope wraps a collection so a future cursor can be added without
// changing the response shape a client already parses.
type listEnvelope struct {
	Items      any    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	Total      int    `json:"total,omitempty"`
}

func writeList(w http.ResponseWriter, items any, total int) {
	httpx.WriteJSON(w, http.StatusOK, listEnvelope{Items: items, Total: total})
}

// requestTimeout is the per-handler bound applied to operations that reach a
// remote host, so one unreachable machine does not tie up a request slot.
const remoteTimeout = 20 * time.Second

func remoteCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), remoteTimeout)
}
