package api

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/axt-term/axt-term/backend/internal/httpx"
	"github.com/axt-term/axt-term/backend/internal/rbac"
	"github.com/axt-term/axt-term/backend/internal/rdp"
	"github.com/axt-term/axt-term/backend/internal/sshx"
	"github.com/axt-term/axt-term/backend/internal/store"
	"github.com/axt-term/axt-term/backend/internal/terminal"
	"github.com/axt-term/axt-term/backend/internal/validate"
)

// pendingHostKeyTTL bounds how long a trust prompt stays answerable. Long enough
// to read a fingerprint and check it against a build record, short enough that a
// stale prompt cannot be confirmed hours later against a key that has since
// changed.
const pendingHostKeyTTL = 5 * time.Minute

// pendingHostKey is a host key awaiting a trust decision.
//
// Held server-side rather than round-tripped through the client, because the
// fingerprint that gets trusted must be the one the server observed. A client
// that could supply the fingerprint could trust an attacker's key.
type pendingHostKey struct {
	Hostname    string
	Port        int
	KeyType     string
	Fingerprint string
	PublicKey   []byte
	CreatedAt   time.Time
}

type pendingHostKeyStore struct {
	mu      sync.Mutex
	entries map[string]pendingHostKey
}

func newPendingHostKeyStore() *pendingHostKeyStore {
	return &pendingHostKeyStore{entries: make(map[string]pendingHostKey)}
}

func pendingKey(userID, hostID string) string { return userID + "|" + hostID }

func (p *pendingHostKeyStore) put(userID, hostID string, entry pendingHostKey) {
	entry.CreatedAt = time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	// Opportunistic sweep, so the map cannot grow from abandoned prompts.
	for k, v := range p.entries {
		if time.Since(v.CreatedAt) > pendingHostKeyTTL {
			delete(p.entries, k)
		}
	}
	p.entries[pendingKey(userID, hostID)] = entry
}

func (p *pendingHostKeyStore) take(userID, hostID string) (pendingHostKey, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.entries[pendingKey(userID, hostID)]
	if !ok {
		return pendingHostKey{}, false
	}
	delete(p.entries, pendingKey(userID, hostID))
	if time.Since(entry.CreatedAt) > pendingHostKeyTTL {
		return pendingHostKey{}, false
	}
	return entry, true
}

func (s *Server) takePendingHostKey(userID, hostID string) (pendingHostKey, bool) {
	return s.pendingKeys.take(userID, hostID)
}

// closeHostConnections drops the pooled transport for a host, used when its
// configuration changes or it is deleted.
func (s *Server) closeHostConnections(hostID string) {
	if s.pool != nil {
		s.pool.CloseHost(hostID)
	}
}

// --------------------------------------------------------------- sessions ---

type createSessionRequest struct {
	HostID  string `json:"host_id"`
	Cols    int    `json:"cols"`
	Rows    int    `json:"rows"`
	Record  bool   `json:"record,omitempty"`
	Command string `json:"command,omitempty"`

	// Desktop geometry, in pixels. A PTY measures itself in cells and a desktop in
	// pixels, so the two cannot share one pair of fields without one of them lying.
	Width  int `json:"width,omitempty"`
	Height int `json:"height,omitempty"`
	DPI    int `json:"dpi,omitempty"`
}

type hostKeyPrompt struct {
	Hostname    string `json:"hostname"`
	Port        int    `json:"port"`
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
	// FirstContact distinguishes "never seen this host" from "the key changed",
	// which are very different situations for the person being asked.
	FirstContact bool `json:"first_contact"`
}

type createSessionResponse struct {
	SessionID string              `json:"session_id,omitempty"`
	State     string              `json:"state"`
	Host      *store.Host         `json:"host,omitempty"`
	// Session is a terminal.Info or an rdp.Info. Both marshal to the shape the
	// client's SessionInfo type describes, differing only in whether they carry
	// cells or pixels.
	Session   any                 `json:"session,omitempty"`
	HostKey   *hostKeyPrompt      `json:"pending_hostkey,omitempty"`
	Banners   []string            `json:"banners,omitempty"`
	Error     *sessionErrorDetail `json:"error,omitempty"`
}

type sessionErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hop     string `json:"hop,omitempty"`
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req createSessionRequest
	if !decode(w, r, &req) {
		return
	}
	p := s.principal(r)

	host, err := s.store.HostByID(r.Context(), req.HostID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !host.Protocol.Implemented() {
		httpx.NotImplemented(w, r, "sessions over "+string(host.Protocol), "phase-4")
		return
	}
	if host.Protocol.Desktop() {
		s.createDesktopSession(w, r, host, req)
		return
	}

	if req.Cols == 0 {
		req.Cols = 80
	}
	if req.Rows == 0 {
		req.Rows = 24
	}
	if err := validate.TerminalSize(req.Cols, req.Rows); err != nil {
		httpx.ValidationFailed(w, r, map[string]any{"cols": err.Error()})
		return
	}
	if req.Record && !p.Has("session.record") {
		httpx.Forbidden(w, r, "recording requires the session.record permission")
		return
	}

	ctx, cancel := remoteCtx(r)
	defer cancel()

	session, err := s.sessions.Create(ctx, terminal.CreateRequest{
		UserID:   p.UserID,
		Username: p.Username,
		Host:     host,
		Cols:     req.Cols,
		Rows:     req.Rows,
		ClientIP: httpx.ClientIP(r.Context()),
		Command:  req.Command,
		Record:   req.Record,
	})
	if err != nil {
		s.respondSessionError(w, r, host, err)
		return
	}

	info := session.Info()
	s.audit.HostAction(r, host, ActionSessionOpen, host.Address(), map[string]any{
		"session_id": session.ID,
		"recording":  session.IsRecording(),
	})

	httpx.WriteJSON(w, http.StatusCreated, createSessionResponse{
		SessionID: session.ID,
		State:     string(info.State),
		Host:      host,
		Session:   &info,
	})
}

// createDesktopSession opens an RDP or VNC session through the guacd bridge.
//
// The permission check is inline rather than on the route because one route serves
// both kinds of session and its declared permission is session.ssh -- the same
// reason the recording check below it is inline. Somebody granted shells is not
// automatically granted desktops: an RDP session carries clipboard and optional
// drive redirection, which is a wider door than a PTY.
func (s *Server) createDesktopSession(w http.ResponseWriter, r *http.Request, host *store.Host, req createSessionRequest) {
	p := s.principal(r)

	if !p.Has(rbac.SessionRDP) {
		httpx.Forbidden(w, r, "opening a remote desktop requires the "+rbac.SessionRDP+" permission")
		return
	}
	if !s.cfg.RDP.Enabled() {
		httpx.WriteErrorDetails(w, r, http.StatusNotImplemented, httpx.CodeNotImplemented,
			"remote desktops are unavailable because no guacd address is configured",
			map[string]any{"setting": "AXT_GUACD_ADDR"})
		return
	}

	ctx, cancel := remoteCtx(r)
	defer cancel()

	session, err := s.desktops.Create(ctx, rdp.CreateRequest{
		UserID:   p.UserID,
		Username: p.Username,
		Host:     host,
		Display:  rdp.Display{Width: req.Width, Height: req.Height, DPI: req.DPI},
		ClientIP: httpx.ClientIP(r.Context()),
	})
	if err != nil {
		s.respondDesktopError(w, r, host, err)
		return
	}

	info := session.Info()
	s.audit.HostAction(r, host, ActionSessionOpen, host.Address(), map[string]any{
		"session_id": session.ID,
		"protocol":   string(host.Protocol),
		"clipboard":  host.RDPOptions.EnableClipboard,
		"drive":      host.RDPOptions.EnableDrive,
	})

	httpx.WriteJSON(w, http.StatusCreated, createSessionResponse{
		SessionID: session.ID,
		State:     string(info.State),
		Host:      host,
		Session:   &info,
	})
}

// respondDesktopError records a failed desktop connection and reports it.
//
// A rejected password and an unreachable gateway are both "it did not connect" to
// the user, and telling them apart is the difference between re-checking a
// credential and telling an operator guacd is down.
func (s *Server) respondDesktopError(w http.ResponseWriter, r *http.Request, host *store.Host, err error) {
	severity := store.SeverityWarning
	detail := map[string]any{"error": err.Error()}

	var remote *rdp.RemoteError
	if errors.As(err, &remote) {
		detail["guacamole_status"] = remote.Status
	}
	if errors.Is(err, rdp.ErrUnavailable) {
		detail["gateway"] = "unreachable"
	}

	s.audit.Record(r, Entry{
		Action:   ActionSessionFailed,
		Target:   host.Address(),
		Host:     host,
		Result:   store.AuditFailure,
		Severity: severity,
		Detail:   detail,
	})
	s.fail(w, r, err)
}

// respondSessionError turns a dial failure into something the UI can act on.
//
// The host-key cases are the interesting ones: an unknown key is a prompt, and a
// changed key is a hard stop that names both fingerprints. Everything else names
// the hop that failed, because "connection refused" without knowing which link
// broke wastes the engineer's time.
func (s *Server) respondSessionError(w http.ResponseWriter, r *http.Request, host *store.Host, err error) {
	p := s.principal(r)

	if unknown, ok := sshx.AsUnknownHostKey(err); ok {
		s.pendingKeys.put(p.UserID, host.ID, pendingHostKey{
			Hostname:    unknown.Hostname,
			Port:        unknown.Port,
			KeyType:     unknown.KeyType,
			Fingerprint: unknown.Fingerprint,
			PublicKey:   unknown.PublicKey,
		})
		s.audit.HostAction(r, host, "hostkey.prompt", unknown.Fingerprint, map[string]any{
			"key_type": unknown.KeyType,
		})
		httpx.WriteJSON(w, http.StatusOK, createSessionResponse{
			State: "pending_hostkey",
			Host:  host,
			HostKey: &hostKeyPrompt{
				Hostname:     unknown.Hostname,
				Port:         unknown.Port,
				KeyType:      unknown.KeyType,
				Fingerprint:  unknown.Fingerprint,
				FirstContact: true,
			},
		})
		return
	}

	if mismatch, ok := sshx.AsMismatchedHostKey(err); ok {
		s.audit.Record(r, Entry{
			Action:   "ssh.hostkey.mismatch",
			Target:   mismatch.Hostname,
			Host:     host,
			Result:   store.AuditFailure,
			Severity: store.SeverityCritical,
			Detail: map[string]any{
				"expected": mismatch.Expected,
				"actual":   mismatch.Actual,
				"key_type": mismatch.KeyType,
			},
		})
		httpx.WriteErrorDetails(w, r, http.StatusConflict, "hostkey_mismatch",
			mismatch.Error(), map[string]any{
				"hostname": mismatch.Hostname,
				"port":     mismatch.Port,
				"key_type": mismatch.KeyType,
				"expected": mismatch.Expected,
				"actual":   mismatch.Actual,
				"remedy":   "verify the host out of band, then revoke the stored key on the Host Keys screen",
			})
		return
	}

	var hopErr *sshx.HopError
	if errors.As(err, &hopErr) {
		s.audit.Record(r, Entry{
			Action:   ActionSessionFailed,
			Target:   hopErr.Addr,
			Host:     host,
			Result:   store.AuditFailure,
			Severity: store.SeverityWarning,
			Detail: map[string]any{
				"hop":   hopErr.Label,
				"index": hopErr.Index + 1,
				"of":    hopErr.Total,
				"error": hopErr.Err.Error(),
			},
		})
		httpx.WriteErrorDetails(w, r, http.StatusBadGateway, httpx.CodeUpstreamFailure,
			hopErr.Error(), map[string]any{
				"hop":       hopErr.Label,
				"hop_index": hopErr.Index + 1,
				"hop_count": hopErr.Total,
			})
		return
	}

	s.audit.Record(r, Entry{
		Action:   ActionSessionFailed,
		Target:   host.Address(),
		Host:     host,
		Result:   store.AuditFailure,
		Severity: store.SeverityWarning,
		Detail:   map[string]any{"error": err.Error()},
	})
	s.fail(w, r, err)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	userID := s.principal(r).UserID

	// One list across both kinds of session. A tab strip does not care which
	// registry a session came from, and a client that had to merge two endpoints
	// would be a client that could get the merge wrong.
	ptys := s.sessions.Infos(userID)
	desktops := s.desktops.Infos(userID)

	infos := make([]any, 0, len(ptys)+len(desktops))
	for i := range ptys {
		infos = append(infos, ptys[i])
	}
	for i := range desktops {
		infos = append(infos, desktops[i])
	}
	writeList(w, infos, len(infos))
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	userID := s.principal(r).UserID
	id := r.PathValue("id")

	if session, err := s.sessions.GetForUser(userID, id); err == nil {
		httpx.WriteJSON(w, http.StatusOK, session.Info())
		return
	}
	desktop, err := s.desktops.GetForUser(userID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, desktop.Info())
}

func (s *Server) handleCloseSession(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	id := r.PathValue("id")

	if session, err := s.sessions.GetForUser(p.UserID, id); err == nil {
		label := session.HostLabel
		session.Close("closed by user")
		s.audit.Success(r, ActionSessionClose, label, map[string]any{"session_id": id})
		httpx.NoContent(w)
		return
	}

	desktop, err := s.desktops.GetForUser(p.UserID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	label := desktop.HostLabel
	desktop.Close("closed by user")
	s.audit.Success(r, ActionSessionClose, label, map[string]any{
		"session_id": id,
		"protocol":   string(desktop.Protocol),
	})
	httpx.NoContent(w)
}

type ticketResponse struct {
	Ticket    string `json:"ticket"`
	ExpiresIn int    `json:"expires_in"`
	// Seq lets a reattaching client ask only for what it missed.
	Seq uint64 `json:"seq"`
}

// handleSessionTicket issues the single-use ticket that authorises a WebSocket.
//
// The purpose is bound to the kind of session, and TicketStore.Consume checks it,
// so a ticket minted for a desktop cannot be spent on /ws/terminal or the reverse.
func (s *Server) handleSessionTicket(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	id := r.PathValue("id")

	if session, err := s.sessions.GetForUser(p.UserID, id); err == nil {
		ticket, terr := s.auth.Tickets().Issue(p.UserID, session.ID, httpx.ClientIP(r.Context()), "terminal")
		if terr != nil {
			s.fail(w, r, terr)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, ticketResponse{
			Ticket:    ticket.Value,
			ExpiresIn: int(time.Until(ticket.ExpiresAt).Seconds()),
			Seq:       session.Info().Seq,
		})
		return
	}

	desktop, err := s.desktops.GetForUser(p.UserID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ticket, err := s.auth.Tickets().Issue(p.UserID, desktop.ID, httpx.ClientIP(r.Context()), "rdp")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// No Seq: a desktop has no byte offset to resume from. Its reattach mechanism
	// is a full repaint, not a delta.
	httpx.WriteJSON(w, http.StatusOK, ticketResponse{
		Ticket:    ticket.Value,
		ExpiresIn: int(time.Until(ticket.ExpiresAt).Seconds()),
	})
}

// handleEventsTicket issues a ticket for the notification socket, which is not
// bound to a session.
func (s *Server) handleEventsTicket(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	ticket, err := s.auth.Tickets().Issue(p.UserID, "", httpx.ClientIP(r.Context()), "events")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ticketResponse{
		Ticket:    ticket.Value,
		ExpiresIn: int(time.Until(ticket.ExpiresAt).Seconds()),
	})
}

type resizeRequest struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
	// Desktop sessions resize in pixels.
	Width  int `json:"width"`
	Height int `json:"height"`
}

func (s *Server) handleResizeSession(w http.ResponseWriter, r *http.Request) {
	var req resizeRequest
	if !decode(w, r, &req) {
		return
	}
	p := s.principal(r)
	id := r.PathValue("id")

	if session, err := s.sessions.GetForUser(p.UserID, id); err == nil {
		if verr := validate.TerminalSize(req.Cols, req.Rows); verr != nil {
			httpx.ValidationFailed(w, r, map[string]any{"cols": verr.Error()})
			return
		}
		if rerr := session.Resize(req.Cols, req.Rows); rerr != nil {
			s.fail(w, r, rerr)
			return
		}
		httpx.NoContent(w)
		return
	}

	desktop, err := s.desktops.GetForUser(p.UserID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if verr := validateDesktopSize(req.Width, req.Height); verr != nil {
		httpx.ValidationFailed(w, r, map[string]any{"width": verr.Error()})
		return
	}
	if err := desktop.Resize(req.Width, req.Height); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// validateDesktopSize bounds a requested desktop geometry.
//
// The same bounds the WebSocket control path enforces; a desktop dimension becomes
// a framebuffer allocation in guacd either way.
func validateDesktopSize(width, height int) error {
	if width < 640 || height < 480 {
		return errors.New("a display smaller than 640x480 is not usable")
	}
	if width > 8192 || height > 8192 {
		return errors.New("a display larger than 8192 pixels on an edge is not supported")
	}
	return nil
}

type recordingRequest struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleSessionRecording(w http.ResponseWriter, r *http.Request) {
	var req recordingRequest
	if !decode(w, r, &req) {
		return
	}
	p := s.principal(r)
	session, err := s.sessions.GetForUser(p.UserID, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}

	if !req.Enabled {
		if err := session.StopRecording(); err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit.Success(r, ActionSessionRecording, session.HostLabel,
			map[string]any{"enabled": false, "session_id": session.ID})
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"recording": false})
		return
	}

	now := time.Now().UTC()
	path := s.cfg.Paths.RecordingsDir + "/" + now.Format("2006-01-02") + "/" +
		now.Format("150405") + "-" + session.ID + ".cast"
	if err := session.StartRecording(path); err != nil {
		s.fail(w, r, err)
		return
	}
	if session.RecordID != "" {
		if err := s.store.SetSessionRecording(r.Context(), session.RecordID, path); err != nil {
			s.log.WarnContext(r.Context(), "could not store recording path")
		}
	}
	s.audit.Record(r, Entry{
		Action:   ActionSessionRecording,
		Target:   session.HostLabel,
		Severity: store.SeverityNotice,
		Detail:   map[string]any{"enabled": true, "session_id": session.ID},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"recording": true})
}

func (s *Server) handleRecentSessions(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 20)
	records, err := s.store.RecentSessions(r.Context(), s.principal(r).UserID, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeList(w, records, len(records))
}

// handleDeleteRecentSession removes one entry from the Recent list.
//
// This edits *history*, not the inventory: the host stays, and so does the audit
// log, which is a separate append-only table this cannot touch. Recorded as a
// notice so that curating the list is itself visible.
func (s *Server) handleDeleteRecentSession(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	id := r.PathValue("id")

	record, err := s.store.SessionRecordByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.DeleteSessionRecord(r.Context(), p.UserID, id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.Record(r, Entry{
		Action:   ActionSessionHistoryDelete,
		Target:   record.HostSnapshot,
		Severity: store.SeverityNotice,
		Detail:   map[string]any{"session_record_id": id},
	})
	httpx.NoContent(w)
}

// handleClearRecentSessions empties the Recent list, leaving live sessions alone.
func (s *Server) handleClearRecentSessions(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)

	removed, err := s.store.DeleteSessionRecordsForUser(r.Context(), p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.Record(r, Entry{
		Action:   ActionSessionHistoryDelete,
		Target:   "all",
		Severity: store.SeverityNotice,
		Detail:   map[string]any{"removed": removed},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"removed": removed})
}
