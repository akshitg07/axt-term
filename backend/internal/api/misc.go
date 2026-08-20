package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/axt-term/axt-term/backend/internal/httpx"
	"github.com/axt-term/axt-term/backend/internal/store"
)

// ------------------------------------------------------------------ search ---

// handleSearch is the unified search behind Ctrl+K.
//
// One query returns hosts, folders, tags, snippets, and workspaces together,
// because an engineer usually remembers *something* about what they want and
// should not have to know which screen it lives on.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	limit := queryInt(r, "limit", 30)

	results, err := s.store.Search(r.Context(), s.principal(r).UserID, query, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeList(w, results, len(results))
}

// --------------------------------------------------------------- settings ---

func (s *Server) handleGetUserSettings(w http.ResponseWriter, r *http.Request) {
	values, err := s.store.UserSettings(r.Context(), s.principal(r).UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if values == nil {
		values = map[string]json.RawMessage{}
	}
	httpx.WriteJSON(w, http.StatusOK, values)
}

// allowedUserSettings bounds what a user may store against their account.
//
// An allow-list rather than free-form storage: without it, the settings table
// becomes an arbitrary per-user key-value store reachable by any authenticated
// request, which is both a storage-growth problem and a place to stash data.
var allowedUserSettings = map[string]bool{
	store.UserSettingTheme:         true,
	store.UserSettingTerminalTheme: true,
	store.UserSettingTerminalFont:  true,
	store.UserSettingTerminalSize:  true,
	store.UserSettingKeybindings:   true,
	store.UserSettingSidebarWidth:  true,
	store.UserSettingLayout:        true,
}

// maxUserSettingBytes bounds one stored value. The layout blob is the largest
// realistic entry and is well under this.
const maxUserSettingBytes = 256 * 1024

func (s *Server) handleSetUserSettings(w http.ResponseWriter, r *http.Request) {
	var req map[string]json.RawMessage
	if !decode(w, r, &req) {
		return
	}

	fields := map[string]any{}
	accepted := make(map[string]json.RawMessage, len(req))
	for key, value := range req {
		if !allowedUserSettings[key] {
			fields[key] = "unknown setting"
			continue
		}
		if len(value) > maxUserSettingBytes {
			fields[key] = "value is too large"
			continue
		}
		accepted[key] = value
	}
	if len(fields) > 0 {
		httpx.ValidationFailed(w, r, fields)
		return
	}

	if err := s.store.SetUserSettings(r.Context(), s.principal(r).UserID, accepted); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	values, err := s.store.AllSettings(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The crypto canary is internal machinery, not a setting an administrator
	// should see or edit.
	delete(values, store.SettingCanary)

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"settings": values,
		"effective": map[string]any{
			"command_logging":  s.cfg.Session.CommandLogging,
			"hostkey_policy":   s.cfg.SSH.HostKeyPolicy,
			"rdp_enabled":      s.cfg.RDP.Enabled(),
			"metrics_enabled":  s.cfg.HTTP.MetricsEnabled,
			"session_idle":     s.cfg.Session.IdleClose.String(),
			"ring_buffer":      s.cfg.Session.RingBufferSize,
			"max_per_user":     s.cfg.Session.MaxPerUser,
			"transfer_workers": s.cfg.Transfer.Workers,
			"legacy_ssh_algos": s.cfg.SSH.LegacyAlgorithms,
			"public_bind":      s.cfg.Tunnels.AllowPublicBind,
		},
		"warnings": s.cfg.Warnings(),
	})
}

// allowedInstanceSettings bounds what an administrator may store.
//
// Anything that changes how the server behaves at the protocol level lives in
// environment variables instead, so it is visible in the deployment
// configuration rather than hidden in a database row.
var allowedInstanceSettings = map[string]bool{
	store.SettingInstanceName:    true,
	store.SettingBrandingMessage: true,
	store.SettingDiscoveryOptIn:  true,
	store.SettingMetricsDashURL:  true,
	store.SettingAIProviderURL:   true,
}

func (s *Server) handleSetSettings(w http.ResponseWriter, r *http.Request) {
	var req map[string]json.RawMessage
	if !decode(w, r, &req) {
		return
	}

	fields := map[string]any{}
	for key := range req {
		if !allowedInstanceSettings[key] {
			fields[key] = "this setting is not configurable through the API; use an environment variable"
		}
	}
	if len(fields) > 0 {
		httpx.ValidationFailed(w, r, fields)
		return
	}

	actorID := s.principal(r).UserID
	changed := make([]string, 0, len(req))
	for key, value := range req {
		if err := s.store.SetSetting(r.Context(), key, value, actorID); err != nil {
			s.fail(w, r, err)
			return
		}
		changed = append(changed, key)
	}

	s.audit.Record(r, Entry{
		Action:   ActionSettingsUpdate,
		Severity: store.SeverityNotice,
		Detail:   map[string]any{"keys": changed},
	})
	httpx.NoContent(w)
}

// ------------------------------------------------------------------- audit ---

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := store.AuditFilter{
		UserID:   q.Get("user_id"),
		HostID:   q.Get("host_id"),
		Action:   q.Get("action"),
		Result:   store.AuditResult(q.Get("result")),
		Severity: store.AuditSeverity(q.Get("severity")),
		Query:    q.Get("q"),
		Limit:    queryInt(r, "limit", 100),
		Cursor:   q.Get("cursor"),
	}
	if from := q.Get("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			filter.From = &t
		}
	}
	if to := q.Get("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			filter.To = &t
		}
	}

	events, next, err := s.store.ListAudit(r.Context(), filter)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, listEnvelope{Items: events, NextCursor: next})
}

func (s *Server) handleAuditActions(w http.ResponseWriter, r *http.Request) {
	actions, err := s.store.AuditActions(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeList(w, actions, len(actions))
}

// --------------------------------------------------------------- transfers ---

func (s *Server) handleListTransfers(w http.ResponseWriter, r *http.Request) {
	transfers, err := s.store.ListTransfers(r.Context(), store.TransferFilter{
		// Scoped to the requesting user in the query rather than filtered
		// afterwards, so a mistake yields an empty list rather than a leak.
		UserID: s.principal(r).UserID,
		Status: store.TransferStatus(r.URL.Query().Get("status")),
		Limit:  queryInt(r, "limit", 100),
		Cursor: r.URL.Query().Get("cursor"),
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeList(w, transfers, len(transfers))
}

func (s *Server) handleRetryTransfer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	transfer, err := s.store.TransferByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if transfer.UserID != s.principal(r).UserID {
		httpx.NotFound(w, r, "transfer")
		return
	}
	if err := s.store.RequeueTransfer(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (s *Server) handleDeleteTransfer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	transfer, err := s.store.TransferByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if transfer.UserID != s.principal(r).UserID {
		httpx.NotFound(w, r, "transfer")
		return
	}
	if err := s.store.DeleteTransfer(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.NoContent(w)
}
