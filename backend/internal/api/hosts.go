package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/axt-term/axt-term/backend/internal/httpx"
	"github.com/axt-term/axt-term/backend/internal/inventory"
	"github.com/axt-term/axt-term/backend/internal/store"
	"github.com/axt-term/axt-term/backend/internal/validate"
	"github.com/google/uuid"
)

// ----------------------------------------------------------------- folders ---

func (s *Server) handleListFolders(w http.ResponseWriter, r *http.Request) {
	folders, err := s.store.ListFolders(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	paths, err := s.store.FolderPaths(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}

	type row struct {
		*store.Folder
		Path string `json:"path"`
	}
	out := make([]row, 0, len(folders))
	for _, f := range folders {
		out = append(out, row{Folder: f, Path: paths[f.ID]})
	}
	writeList(w, out, len(out))
}

type folderRequest struct {
	Name      string `json:"name"`
	ParentID  string `json:"parent_id,omitempty"`
	Icon      string `json:"icon,omitempty"`
	Color     string `json:"color,omitempty"`
	SortOrder int    `json:"sort_order,omitempty"`
}

func (s *Server) handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	var req folderRequest
	if !decode(w, r, &req) {
		return
	}

	v := &validate.Errors{}
	v.Check("name", validate.Name(req.Name, 80))
	v.Check("color", validate.Color(req.Color))
	if v.Any() {
		httpx.ValidationFailed(w, r, v.Map())
		return
	}

	folder := &store.Folder{
		ID:        uuid.NewString(),
		ParentID:  req.ParentID,
		Name:      strings.TrimSpace(req.Name),
		Icon:      req.Icon,
		Color:     req.Color,
		SortOrder: req.SortOrder,
	}
	if err := s.store.CreateFolder(r.Context(), folder); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.Success(r, ActionFolderCreate, folder.Name, nil)
	httpx.WriteJSON(w, http.StatusCreated, folder)
}

func (s *Server) handleUpdateFolder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req folderRequest
	if !decode(w, r, &req) {
		return
	}

	folder, err := s.store.FolderByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	v := &validate.Errors{}
	v.Check("name", validate.Name(req.Name, 80))
	v.Check("color", validate.Color(req.Color))
	if v.Any() {
		httpx.ValidationFailed(w, r, v.Map())
		return
	}

	folder.Name = strings.TrimSpace(req.Name)
	folder.Icon = req.Icon
	folder.Color = req.Color
	folder.SortOrder = req.SortOrder

	if err := s.store.UpdateFolder(r.Context(), folder); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.Success(r, ActionFolderUpdate, folder.Name, nil)
	httpx.WriteJSON(w, http.StatusOK, folder)
}

func (s *Server) handleDeleteFolder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Orphan is the default: deleting a folder is a filing decision, and it must
	// not silently destroy inventory. Cascade has to be asked for.
	strategy := store.StrategyOrphan
	if r.URL.Query().Get("strategy") == "cascade" {
		strategy = store.StrategyCascade
	}

	folder, err := s.store.FolderByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.DeleteFolder(r.Context(), id, strategy); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.Record(r, Entry{
		Action:   ActionFolderDelete,
		Target:   folder.Name,
		Severity: store.SeverityNotice,
		Detail:   map[string]any{"strategy": string(strategy)},
	})
	httpx.NoContent(w)
}

type moveFolderRequest struct {
	ParentID  string `json:"parent_id"`
	SortOrder int    `json:"sort_order"`
}

func (s *Server) handleMoveFolder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req moveFolderRequest
	if !decode(w, r, &req) {
		return
	}
	if err := s.store.MoveFolder(r.Context(), id, req.ParentID, req.SortOrder); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.NoContent(w)
}

// ------------------------------------------------------------------- hosts ---

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.HostFilter{
		Query:         q.Get("q"),
		FolderID:      q.Get("folder_id"),
		Tag:           q.Get("tag"),
		Protocol:      store.Protocol(q.Get("protocol")),
		OSFamily:      store.OSFamily(q.Get("os_family")),
		FavoritesOnly: queryBool(r, "favorite"),
		Sort:          q.Get("sort"),
	}
	hosts, err := s.store.ListHosts(r.Context(), filter)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeList(w, hosts, len(hosts))
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.HostByID(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, host)
}

type hostRequest struct {
	Name                 string               `json:"name"`
	Hostname             string               `json:"hostname"`
	Port                 int                  `json:"port,omitempty"`
	Protocol             store.Protocol       `json:"protocol,omitempty"`
	FolderID             string               `json:"folder_id,omitempty"`
	Username             string               `json:"username,omitempty"`
	AuthMethod           store.AuthMethod     `json:"auth_method,omitempty"`
	CredentialID         string               `json:"credential_id,omitempty"`
	JumpHostID           string               `json:"jump_host_id,omitempty"`
	OSFamily             store.OSFamily       `json:"os_family,omitempty"`
	Color                string               `json:"color,omitempty"`
	Icon                 string               `json:"icon,omitempty"`
	Notes                string               `json:"notes,omitempty"`
	IsFavorite           bool                 `json:"is_favorite,omitempty"`
	HealthCheckEnabled   bool                 `json:"health_check_enabled,omitempty"`
	HealthCheckIntervalS int                  `json:"health_check_interval_s,omitempty"`
	CommandLogging       store.CommandLogging `json:"command_logging,omitempty"`
	RDPOptions           store.RDPOptions     `json:"rdp_options,omitempty"`
	Tags                 []string             `json:"tags,omitempty"`
}

func (req hostRequest) toInput(actorID string) inventory.HostInput {
	return inventory.HostInput{
		Name:                 req.Name,
		Hostname:             req.Hostname,
		Port:                 req.Port,
		Protocol:             req.Protocol,
		FolderID:             req.FolderID,
		Username:             req.Username,
		AuthMethod:           req.AuthMethod,
		CredentialID:         req.CredentialID,
		JumpHostID:           req.JumpHostID,
		OSFamily:             req.OSFamily,
		Color:                req.Color,
		Icon:                 req.Icon,
		Notes:                req.Notes,
		IsFavorite:           req.IsFavorite,
		HealthCheckEnabled:   req.HealthCheckEnabled,
		HealthCheckIntervalS: req.HealthCheckIntervalS,
		CommandLogging:       req.CommandLogging,
		RDPOptions:           req.RDPOptions,
		Tags:                 req.Tags,
		ActorID:              actorID,
	}
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	var req hostRequest
	if !decode(w, r, &req) {
		return
	}
	host, err := s.inventory.CreateHost(r.Context(), req.toInput(s.principal(r).UserID))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.HostAction(r, host, ActionHostCreate, host.Name, map[string]any{
		"protocol": string(host.Protocol),
		"address":  host.Address(),
	})
	httpx.WriteJSON(w, http.StatusCreated, host)
}

func (s *Server) handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req hostRequest
	if !decode(w, r, &req) {
		return
	}

	before, err := s.store.HostByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	host, err := s.inventory.UpdateHost(r.Context(), id, req.toInput(s.principal(r).UserID))
	if err != nil {
		s.fail(w, r, err)
		return
	}

	// A change to where or how we connect must not keep serving a pooled
	// transport built from the old configuration.
	if before.Hostname != host.Hostname || before.Port != host.Port ||
		before.CredentialID != host.CredentialID || before.JumpHostID != host.JumpHostID ||
		before.Username != host.Username || before.AuthMethod != host.AuthMethod {
		s.closeHostConnections(host.ID)
	}

	s.audit.HostAction(r, host, ActionHostUpdate, host.Name, nil)
	httpx.WriteJSON(w, http.StatusOK, host)
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	host, err := s.store.HostByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.DeleteHost(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.closeHostConnections(id)
	s.audit.Record(r, Entry{
		Action:   ActionHostDelete,
		Target:   host.Name,
		Host:     host,
		Severity: store.SeverityNotice,
	})
	httpx.NoContent(w)
}

type favoriteRequest struct {
	IsFavorite bool `json:"is_favorite"`
}

func (s *Server) handleFavoriteHost(w http.ResponseWriter, r *http.Request) {
	var req favoriteRequest
	if !decode(w, r, &req) {
		return
	}
	if err := s.store.SetHostFavorite(r.Context(), r.PathValue("id"), req.IsFavorite); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.NoContent(w)
}

func (s *Server) handleDuplicateHost(w http.ResponseWriter, r *http.Request) {
	source, err := s.store.HostByID(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}

	in := inventory.HostInput{
		Name:                 uniqueCopyName(source.Name),
		Hostname:             source.Hostname,
		Port:                 source.Port,
		Protocol:             source.Protocol,
		FolderID:             source.FolderID,
		Username:             source.Username,
		AuthMethod:           source.AuthMethod,
		CredentialID:         source.CredentialID,
		JumpHostID:           source.JumpHostID,
		OSFamily:             source.OSFamily,
		Color:                source.Color,
		Icon:                 source.Icon,
		Notes:                source.Notes,
		HealthCheckEnabled:   source.HealthCheckEnabled,
		HealthCheckIntervalS: source.HealthCheckIntervalS,
		CommandLogging:       source.CommandLogging,
		RDPOptions:           source.RDPOptions,
		Tags:                 source.Tags,
		ActorID:              s.principal(r).UserID,
	}
	host, err := s.inventory.CreateHost(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.HostAction(r, host, ActionHostCreate, host.Name, map[string]any{"duplicated_from": source.ID})
	httpx.WriteJSON(w, http.StatusCreated, host)
}

func uniqueCopyName(name string) string {
	const suffix = " (copy)"
	if len(name)+len(suffix) > 120 {
		name = name[:120-len(suffix)]
	}
	return name + suffix
}

func (s *Server) handleTestHost(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.HostByID(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}

	ctx, cancel := remoteCtx(r)
	defer cancel()

	result := s.inventory.Probe(ctx, host, 5*time.Second)
	s.audit.HostAction(r, host, ActionHostTest, host.Address(), map[string]any{
		"reachable":  result.Reachable,
		"latency_ms": result.LatencyMS,
	})
	httpx.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleHostActions(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.HostByID(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}

	actions := s.inventory.ActionsFor(host)
	p := s.principal(r)

	// Filter to what this user may actually do, so the UI never offers an action
	// that will be refused.
	visible := make([]inventory.Action, 0, len(actions))
	for _, a := range actions {
		if a.Permission == "" || p.Has(a.Permission) {
			visible = append(visible, a)
		}
	}
	writeList(w, visible, len(visible))
}

// ------------------------------------------------------------------- tags ---

func (s *Server) handleListTags(w http.ResponseWriter, r *http.Request) {
	tags, err := s.store.ListTags(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeList(w, tags, len(tags))
}

type tagRequest struct {
	Name  string `json:"name"`
	Color string `json:"color,omitempty"`
}

func (s *Server) handleCreateTag(w http.ResponseWriter, r *http.Request) {
	var req tagRequest
	if !decode(w, r, &req) {
		return
	}

	v := &validate.Errors{}
	v.Check("name", validate.Tag(req.Name))
	v.Check("color", validate.Color(req.Color))
	if v.Any() {
		httpx.ValidationFailed(w, r, v.Map())
		return
	}

	tag := &store.Tag{ID: uuid.NewString(), Name: strings.TrimSpace(req.Name), Color: req.Color}
	if err := s.store.CreateTag(r.Context(), tag); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.Success(r, ActionTagCreate, tag.Name, nil)
	httpx.WriteJSON(w, http.StatusCreated, tag)
}

func (s *Server) handleDeleteTag(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteTag(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.Success(r, ActionTagDelete, r.PathValue("id"), nil)
	httpx.NoContent(w)
}

// --------------------------------------------------------------- host keys ---

func (s *Server) handleListHostKeys(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if hostname := q.Get("hostname"); hostname != "" {
		port, _ := strconv.Atoi(q.Get("port"))
		if port == 0 {
			port = 22
		}
		keys, err := s.store.HostKeysFor(r.Context(), hostname, port)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writeList(w, keys, len(keys))
		return
	}

	keys, err := s.store.ListHostKeys(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeList(w, keys, len(keys))
}

type trustHostKeyRequest struct {
	HostID string `json:"host_id"`
	// Fingerprint is echoed back from the pending prompt and must match what the
	// server actually observed. It exists so a stale prompt cannot silently trust
	// a key that changed between the prompt and the confirmation.
	Fingerprint string `json:"fingerprint"`
}

func (s *Server) handleTrustHostKey(w http.ResponseWriter, r *http.Request) {
	var req trustHostKeyRequest
	if !decode(w, r, &req) {
		return
	}
	p := s.principal(r)

	pending, ok := s.takePendingHostKey(p.UserID, req.HostID)
	if !ok {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeConflict,
			"there is no pending host key for this host; start the connection again")
		return
	}
	// The fingerprint trusted is the one the server saw, never one supplied by the
	// client. The client's value is only compared, so a tampered request fails
	// rather than trusting something arbitrary.
	if req.Fingerprint != "" && req.Fingerprint != pending.Fingerprint {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeConflict,
			"the host key changed since it was shown to you; start again and check the new fingerprint")
		return
	}

	key := &store.HostKey{
		ID:                uuid.NewString(),
		Hostname:          pending.Hostname,
		Port:              pending.Port,
		KeyType:           pending.KeyType,
		FingerprintSHA256: pending.Fingerprint,
		PublicKey:         pending.PublicKey,
		TrustedBy:         p.UserID,
	}
	if err := s.store.TrustHostKey(r.Context(), key); err != nil {
		s.fail(w, r, err)
		return
	}

	s.audit.Record(r, Entry{
		Action:   ActionHostKeyTrust,
		Target:   pending.Hostname + ":" + strconv.Itoa(pending.Port),
		Severity: store.SeverityNotice,
		Detail: map[string]any{
			"key_type":    pending.KeyType,
			"fingerprint": pending.Fingerprint,
		},
	})
	httpx.WriteJSON(w, http.StatusOK, key)
}

func (s *Server) handleRevokeHostKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.RevokeHostKey(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.Record(r, Entry{
		Action:   ActionHostKeyRevoke,
		Target:   id,
		Severity: store.SeverityWarning,
	})
	httpx.NoContent(w)
}
