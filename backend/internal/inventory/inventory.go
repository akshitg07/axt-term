// Package inventory owns hosts, folders, tags, and the resolution of a host into
// the connection chain the SSH engine needs.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/axt-term/axt-term/backend/internal/credentials"
	"github.com/axt-term/axt-term/backend/internal/events"
	"github.com/axt-term/axt-term/backend/internal/sshx"
	"github.com/axt-term/axt-term/backend/internal/store"
	"github.com/axt-term/axt-term/backend/internal/validate"
	"github.com/google/uuid"
)

// Errors returned by the service.
var (
	// ErrPromptedAuthUnavailable is returned for hosts configured to ask for a
	// password at connect time. The schema supports it and the UI labels it
	// Coming Soon; the engine gains it in Phase 2 alongside the RDP credential
	// prompt, which needs the same plumbing.
	ErrPromptedAuthUnavailable = errors.New(
		"inventory: interactive credential prompts are not implemented yet; attach a credential profile to this host")

	ErrNoCredential = errors.New("inventory: host has no credential attached")
	ErrNoUsername   = errors.New("inventory: no username configured for this host or its credential")
)

// Config configures the service.
type Config struct {
	AgentSocket string
	MaxHops     int
}

// Service manages the inventory.
type Service struct {
	store *store.Store
	creds *credentials.Service
	bus   *events.Bus
	cfg   Config
	log   *slog.Logger
}

// NewService wires the service.
func NewService(st *store.Store, creds *credentials.Service, bus *events.Bus, cfg Config, log *slog.Logger) *Service {
	if cfg.MaxHops <= 0 {
		cfg.MaxHops = 5
	}
	return &Service{store: st, creds: creds, bus: bus, cfg: cfg, log: log}
}

// ResolveChain turns a host into the hops needed to reach it, credentials
// included.
//
// Matches sshx.ChainResolver, so it is handed straight to the connection pool.
// The returned hops carry plaintext secrets; the pool zeroes them once the
// handshake is done.
func (s *Service) ResolveChain(ctx context.Context, hostID string) ([]sshx.Hop, error) {
	chain, err := s.store.JumpChain(ctx, hostID, s.cfg.MaxHops)
	if err != nil {
		return nil, err
	}

	hops := make([]sshx.Hop, 0, len(chain))
	// On any failure part-way through a chain, secrets already resolved must not
	// be left in memory.
	cleanup := func() {
		for i := range hops {
			for _, b := range [][]byte{hops[i].Auth.Password, hops[i].Auth.PrivateKey, hops[i].Auth.Passphrase} {
				for j := range b {
					b[j] = 0
				}
			}
		}
	}

	for _, host := range chain {
		auth, err := s.resolveAuth(ctx, host)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("%s: %w", host.Name, err)
		}
		hops = append(hops, sshx.Hop{
			HostID:   host.ID,
			Label:    host.Name,
			Hostname: host.Hostname,
			Port:     host.Port,
			Auth:     auth,
		})
	}
	return hops, nil
}

func (s *Service) resolveAuth(ctx context.Context, host *store.Host) (sshx.Auth, error) {
	auth := sshx.Auth{Username: host.Username}

	switch host.AuthMethod {
	case store.AuthAgent:
		if s.cfg.AgentSocket == "" {
			return auth, errors.New("agent authentication is selected but no agent socket is configured (set AXT_SSH_AGENT_SOCKET)")
		}
		auth.UseAgent = true
		auth.AgentSocket = s.cfg.AgentSocket

	case store.AuthPasswordPrompt, store.AuthKeyPrompt:
		return auth, ErrPromptedAuthUnavailable

	default: // store.AuthCredential
		if host.CredentialID == "" {
			return auth, ErrNoCredential
		}
		resolved, err := s.creds.Resolve(ctx, host.CredentialID)
		if err != nil {
			return auth, err
		}
		// The host's own username wins when set, so one credential can serve
		// hosts with different accounts.
		if auth.Username == "" {
			auth.Username = resolved.Username
		}
		auth.Password = resolved.Password
		auth.PrivateKey = resolved.PrivateKey
		auth.Passphrase = resolved.Passphrase
		if resolved.Kind == store.CredSSHAgent {
			auth.UseAgent = true
			auth.AgentSocket = s.cfg.AgentSocket
		}
	}

	if auth.Username == "" {
		return auth, ErrNoUsername
	}
	return auth, nil
}

// HostInput carries a host create or update.
type HostInput struct {
	Name                 string
	Hostname             string
	Port                 int
	Protocol             store.Protocol
	FolderID             string
	Username             string
	AuthMethod           store.AuthMethod
	CredentialID         string
	JumpHostID           string
	OSFamily             store.OSFamily
	Color                string
	Icon                 string
	Notes                string
	IsFavorite           bool
	HealthCheckEnabled   bool
	HealthCheckIntervalS int
	CommandLogging       store.CommandLogging
	RDPOptions           store.RDPOptions
	Tags                 []string
	ActorID              string
}

// Validate checks the input and fills in defaults.
func (in *HostInput) Validate() *validate.Errors {
	v := &validate.Errors{}

	in.Name = strings.TrimSpace(in.Name)
	in.Hostname = strings.TrimSpace(in.Hostname)

	v.Check("name", validate.Name(in.Name, 120))
	v.Check("hostname", validate.Hostname(in.Hostname))

	if in.Protocol == "" {
		in.Protocol = store.ProtocolSSH
	}
	if !in.Protocol.Valid() {
		v.Add("protocol", "must be ssh, sftp, rdp, vnc, telnet, serial, or winrm")
	}
	if in.Port == 0 {
		in.Port = in.Protocol.DefaultPort()
	}
	v.Check("port", validate.Port(in.Port))

	if in.AuthMethod == "" {
		in.AuthMethod = store.AuthCredential
	}
	if !in.AuthMethod.Valid() {
		v.Add("auth_method", "must be credential, agent, password_prompt, or key_prompt")
	}
	if in.OSFamily == "" {
		in.OSFamily = store.OSUnknown
	}
	if !in.OSFamily.Valid() {
		v.Add("os_family", "must be linux, windows, bsd, macos, network, or unknown")
	}
	if in.CommandLogging == "" {
		in.CommandLogging = store.LoggingInherit
	}
	if !in.CommandLogging.Valid() {
		v.Add("command_logging", "must be inherit, off, commands, or full")
	}

	v.Check("username", validate.Username(in.Username))
	v.Check("color", validate.Color(in.Color))

	if in.HealthCheckEnabled && in.HealthCheckIntervalS < 30 {
		// A tighter interval would mean hammering an estate of hundreds of hosts,
		// which the design rules out explicitly.
		in.HealthCheckIntervalS = 300
	}
	if in.HealthCheckIntervalS == 0 {
		in.HealthCheckIntervalS = 300
	}

	for _, tag := range in.Tags {
		if err := validate.Tag(tag); err != nil {
			v.Add("tags", fmt.Sprintf("%q: %s", tag, err))
			break
		}
	}
	return v
}

// CreateHost adds a host.
func (s *Service) CreateHost(ctx context.Context, in HostInput) (*store.Host, error) {
	if v := in.Validate(); v.Any() {
		return nil, v
	}
	host := hostFromInput(uuid.NewString(), in)
	host.CreatedBy = in.ActorID
	if err := s.store.CreateHost(ctx, host, in.Tags); err != nil {
		return nil, err
	}
	return s.store.HostByID(ctx, host.ID)
}

// UpdateHost replaces a host's fields.
func (s *Service) UpdateHost(ctx context.Context, id string, in HostInput) (*store.Host, error) {
	if v := in.Validate(); v.Any() {
		return nil, v
	}
	existing, err := s.store.HostByID(ctx, id)
	if err != nil {
		return nil, err
	}
	host := hostFromInput(id, in)
	host.CreatedBy = existing.CreatedBy
	host.CreatedAt = existing.CreatedAt

	if err := s.store.UpdateHost(ctx, host, in.Tags); err != nil {
		return nil, err
	}
	return s.store.HostByID(ctx, id)
}

func hostFromInput(id string, in HostInput) *store.Host {
	return &store.Host{
		ID:                   id,
		Name:                 in.Name,
		Hostname:             in.Hostname,
		Port:                 in.Port,
		Protocol:             in.Protocol,
		FolderID:             in.FolderID,
		Username:             in.Username,
		AuthMethod:           in.AuthMethod,
		CredentialID:         in.CredentialID,
		JumpHostID:           in.JumpHostID,
		OSFamily:             in.OSFamily,
		Color:                in.Color,
		Icon:                 in.Icon,
		Notes:                in.Notes,
		IsFavorite:           in.IsFavorite,
		HealthCheckEnabled:   in.HealthCheckEnabled,
		HealthCheckIntervalS: in.HealthCheckIntervalS,
		CommandLogging:       in.CommandLogging,
		RDPOptions:           in.RDPOptions,
	}
}

// Action is one contextual action a host supports.
//
// The server decides this rather than the frontend, so a Linux SSH box, a Windows
// RDP host, and a switch each offer only what applies. A plugin can extend the
// list in Phase 4 without a frontend change.
type Action struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Icon        string `json:"icon"`
	Group       string `json:"group"`
	Permission  string `json:"permission"`
	Implemented bool   `json:"implemented"`
	Phase       string `json:"phase,omitempty"`
}

// ActionsFor returns the contextual actions for a host.
func (s *Service) ActionsFor(host *store.Host) []Action {
	var actions []Action

	switch host.Protocol {
	case store.ProtocolSSH, store.ProtocolSFTP:
		actions = append(actions,
			Action{ID: "terminal", Label: "Terminal", Icon: "terminal", Group: "connect", Permission: "session.ssh", Implemented: true},
			Action{ID: "files", Label: "Files", Icon: "folder", Group: "connect", Permission: "file.read", Implemented: true},
			Action{ID: "system", Label: "System", Icon: "activity", Group: "inspect", Permission: "service.read", Implemented: true},
			Action{ID: "processes", Label: "Processes", Icon: "list", Group: "inspect", Permission: "service.read", Implemented: false, Phase: "phase-2"},
			Action{ID: "services", Label: "Services", Icon: "settings", Group: "manage", Permission: "service.read", Implemented: false, Phase: "phase-2"},
			Action{ID: "logs", Label: "Logs", Icon: "file-text", Group: "inspect", Permission: "file.read", Implemented: false, Phase: "phase-3"},
			Action{ID: "tunnels", Label: "Tunnels", Icon: "shuffle", Group: "manage", Permission: "tunnel.write", Implemented: false, Phase: "phase-2"},
		)
		if host.OSFamily == store.OSLinux || host.OSFamily == store.OSUnknown {
			actions = append(actions,
				Action{ID: "docker", Label: "Docker", Icon: "box", Group: "manage", Permission: "docker.read", Implemented: false, Phase: "phase-3"})
		}

	case store.ProtocolRDP:
		actions = append(actions,
			Action{ID: "rdp", Label: "Remote Desktop", Icon: "monitor", Group: "connect", Permission: "session.rdp", Implemented: false, Phase: "phase-2"},
			Action{ID: "files", Label: "Files", Icon: "folder", Group: "connect", Permission: "file.read", Implemented: false, Phase: "phase-2"},
			Action{ID: "services", Label: "Services", Icon: "settings", Group: "manage", Permission: "service.read", Implemented: false, Phase: "phase-3"},
		)

	case store.ProtocolVNC, store.ProtocolTelnet, store.ProtocolSerial, store.ProtocolWinRM:
		actions = append(actions,
			Action{ID: "connect", Label: "Connect", Icon: "plug", Group: "connect", Permission: "session.rdp", Implemented: false, Phase: "phase-4"})
	}

	actions = append(actions,
		Action{ID: "edit", Label: "Edit host", Icon: "pencil", Group: "manage", Permission: "host.write", Implemented: true},
		Action{ID: "test", Label: "Test connection", Icon: "check", Group: "manage", Permission: "host.read", Implemented: true},
	)
	return actions
}

// ProbeResult is the outcome of a connectivity test.
type ProbeResult struct {
	Reachable   bool   `json:"reachable"`
	LatencyMS   int    `json:"latency_ms"`
	Banner      string `json:"banner,omitempty"`
	Error       string `json:"error,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Probe tests whether a host is reachable, without opening a shell.
//
// Deliberately stops at the TCP layer and the SSH identification string: it
// answers "will connecting work" without authenticating, without leaving a
// session record, and without touching the host's auth logs.
func (s *Service) Probe(ctx context.Context, host *store.Host, timeout time.Duration) ProbeResult {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	addr := net.JoinHostPort(host.Hostname, strconv.Itoa(host.Port))

	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ProbeResult{Reachable: false, Error: err.Error()}
	}
	defer func() { _ = conn.Close() }()

	latency := int(time.Since(start).Milliseconds())
	result := ProbeResult{Reachable: true, LatencyMS: latency}

	// SSH servers send an identification string immediately, before any
	// authentication. Reading it costs nothing and tells the operator what is
	// listening.
	if host.Protocol == store.ProtocolSSH || host.Protocol == store.ProtocolSFTP {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 255)
		if n, rerr := conn.Read(buf); rerr == nil && n > 0 {
			result.Banner = validate.SafeDisplay(strings.TrimSpace(string(buf[:n])))
		}
	}
	return result
}

// HealthChecker periodically probes hosts that have checking enabled.
//
// Only hosts explicitly opted in are polled, and never more often than their own
// interval. Polling an entire inventory by default would generate constant
// connection attempts against every machine an engineer owns, which shows up in
// their auth logs and their intrusion detection.
type HealthChecker struct {
	svc      *Service
	store    *store.Store
	bus      *events.Bus
	log      *slog.Logger
	slowMS   int
	batch    int
	interval time.Duration
}

// NewHealthChecker creates the checker.
func NewHealthChecker(svc *Service, st *store.Store, bus *events.Bus, log *slog.Logger) *HealthChecker {
	return &HealthChecker{
		svc:      svc,
		store:    st,
		bus:      bus,
		log:      log,
		slowMS:   500,
		batch:    20,
		interval: 30 * time.Second,
	}
}

// Run checks due hosts until ctx is cancelled.
func (h *HealthChecker) Run(ctx context.Context) {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.tick(ctx)
		}
	}
}

func (h *HealthChecker) tick(ctx context.Context) {
	hosts, err := h.store.HostsDueForHealthCheck(ctx, time.Now().UTC(), h.batch)
	if err != nil {
		h.log.WarnContext(ctx, "could not list hosts due for health check", slog.Any("error", err))
		return
	}
	for _, host := range hosts {
		select {
		case <-ctx.Done():
			return
		default:
		}
		h.check(ctx, host)
	}
}

func (h *HealthChecker) check(ctx context.Context, host *store.Host) {
	probe := h.svc.Probe(ctx, host, 5*time.Second)

	status := store.HealthOffline
	var latency *int
	switch {
	case probe.Reachable && probe.LatencyMS > h.slowMS:
		status = store.HealthSlow
		latency = &probe.LatencyMS
	case probe.Reachable:
		status = store.HealthOnline
		latency = &probe.LatencyMS
	}

	record := &store.HostHealth{
		HostID:    host.ID,
		Status:    status,
		LatencyMS: latency,
		CheckedAt: time.Now().UTC(),
		Error:     probe.Error,
	}
	if err := h.store.UpsertHostHealth(ctx, record); err != nil {
		h.log.WarnContext(ctx, "could not record host health",
			slog.String("host", host.Name), slog.Any("error", err))
		return
	}

	// Only publish when the status changed, so a stable estate produces no event
	// traffic at all.
	if host.Health == nil || host.Health.Status != status {
		h.bus.PublishHostHealth(host.ID, string(status), latency)
	}
}
