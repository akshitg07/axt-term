package rdp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/axt-term/axt-term/backend/internal/credentials"
	"github.com/axt-term/axt-term/backend/internal/events"
	"github.com/axt-term/axt-term/backend/internal/store"
	"github.com/axt-term/axt-term/backend/internal/terminal"
	"github.com/google/uuid"
)

// Registry errors.
var (
	ErrNotFound    = errors.New("rdp: session not found")
	ErrLimit       = errors.New("rdp: session limit reached")
	ErrUnsupported = errors.New("rdp: protocol is not served by the desktop gateway")
	ErrDisabled    = errors.New("rdp: no guacd address is configured")
)

// CredentialResolver decrypts a credential for use in a handshake.
//
// An interface rather than the concrete service so the registry can be tested
// without a keyring, and so the only production implementation stays the one
// audited path from ciphertext to plaintext.
type CredentialResolver interface {
	Resolve(ctx context.Context, credentialID string) (*credentials.Resolved, error)
}

// Config configures the registry.
type Config struct {
	GuacdAddr  string
	MaxPerUser int
	IdleClose  time.Duration
}

func (c Config) withDefaults() Config {
	if c.MaxPerUser <= 0 {
		// Lower than the terminal cap: each desktop holds a guacd connection and a
		// framebuffer, which cost far more than a PTY and a ring buffer.
		c.MaxPerUser = 10
	}
	if c.IdleClose <= 0 {
		c.IdleClose = 30 * time.Minute
	}
	return c
}

// Enabled reports whether desktop sessions can be opened at all.
func (c Config) Enabled() bool { return c.GuacdAddr != "" }

// Registry holds every live desktop session in this process.
type Registry struct {
	cfg   Config
	creds CredentialResolver
	store *store.Store
	bus   *events.Bus
	log   *slog.Logger

	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewRegistry creates the registry.
func NewRegistry(cfg Config, creds CredentialResolver, st *store.Store, bus *events.Bus, log *slog.Logger) *Registry {
	return &Registry{
		cfg:      cfg.withDefaults(),
		creds:    creds,
		store:    st,
		bus:      bus,
		log:      log,
		sessions: make(map[string]*Session),
	}
}

// Enabled reports whether the gateway is configured.
func (r *Registry) Enabled() bool { return r.cfg.Enabled() }

// GuacdAddr returns the configured gateway address, for the readiness probe.
func (r *Registry) GuacdAddr() string { return r.cfg.GuacdAddr }

// CreateRequest describes a new desktop session.
type CreateRequest struct {
	UserID   string
	Username string
	Host     *store.Host
	Display  Display
	ClientIP string
}

// Create opens a desktop session.
//
// The whole handshake happens here, synchronously, for the same reason the SSH
// dial does: a rejected password or an unreachable gateway must be the result of
// the create call. Reporting it later over a WebSocket would leave the UI showing
// a connecting tab with no way to explain itself.
func (r *Registry) Create(ctx context.Context, req CreateRequest) (*Session, error) {
	if req.Host == nil {
		return nil, errors.New("rdp: host is required")
	}
	if !req.Host.Protocol.Desktop() {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, req.Host.Protocol)
	}
	if !r.cfg.Enabled() {
		return nil, ErrDisabled
	}
	if n := r.countForUser(req.UserID); n >= r.cfg.MaxPerUser {
		return nil, fmt.Errorf("%w: %d desktops already open", ErrLimit, n)
	}

	display := DisplayFor(req.Host, req.Display)

	// Decrypt as late as possible and wipe as early as possible: the plaintext
	// exists only for the span of the handshake.
	var resolved *credentials.Resolved
	if req.Host.CredentialID != "" {
		var err error
		resolved, err = r.creds.Resolve(ctx, req.Host.CredentialID)
		if err != nil {
			return nil, err
		}
		defer resolved.Zero()
	}

	params := BuildParams(req.Host, resolved, display)

	client, err := Dial(ctx, r.cfg.GuacdAddr)
	if err != nil {
		return nil, err
	}
	if err := client.Handshake(ctx, GuacProtocol(req.Host.Protocol), params, display); err != nil {
		_ = client.Close()
		return nil, err
	}

	now := time.Now().UTC()
	sess := &Session{
		ID:           uuid.NewString(),
		UserID:       req.UserID,
		HostID:       req.Host.ID,
		HostLabel:    req.Host.Label(),
		Protocol:     req.Host.Protocol,
		CreatedAt:    now,
		ClientIP:     req.ClientIP,
		guacdAddr:    r.cfg.GuacdAddr,
		driveEnabled: req.Host.RDPOptions.EnableDrive,
		owner:        client,
		state:        terminal.StateConnected,
		display:      display,
		done:         make(chan struct{}),
		log:          r.log,
	}
	sess.onClose = func(s *Session) { r.onSessionClosed(s) }

	// History before the relay starts, so a desktop that dies immediately still
	// appears in Recent with a reason.
	record := &store.SessionRecord{
		ID:           uuid.NewString(),
		UserID:       req.UserID,
		HostID:       req.Host.ID,
		HostSnapshot: req.Host.Label(),
		Protocol:     req.Host.Protocol,
		Status:       store.SessionConnected,
		ClientIP:     req.ClientIP,
		StartedAt:    now,
	}
	if err := r.store.CreateSessionRecord(ctx, record); err != nil {
		r.log.WarnContext(ctx, "could not record desktop session history", slog.Any("error", err))
	} else {
		sess.RecordID = record.ID
	}

	r.mu.Lock()
	r.sessions[sess.ID] = sess
	r.mu.Unlock()

	go sess.pump(client, true)

	r.log.InfoContext(ctx, "desktop session opened",
		slog.String("session_id", sess.ID),
		slog.String("user", req.Username),
		slog.String("host", sess.HostLabel),
		slog.String("protocol", string(req.Host.Protocol)),
		slog.String("guacd_version", client.Version()))

	r.bus.PublishSessionState(req.UserID, sess.ID, string(terminal.StateConnected), "")
	return sess, nil
}

func (r *Registry) onSessionClosed(s *Session) {
	r.mu.Lock()
	delete(r.sessions, s.ID)
	r.mu.Unlock()

	in, out := s.Bytes()
	reason := s.ExitReason()

	// Independent context: the request that opened the session is long gone, and a
	// cancelled context must not stop history being written.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.RecordID != "" {
		status := store.SessionClosed
		switch s.State() {
		case terminal.StateFailed:
			status = store.SessionFailed
		case terminal.StateDisconnected:
			status = store.SessionDisconnected
		}
		if err := r.store.CloseSessionRecord(ctx, s.RecordID, status, reason, in, out); err != nil {
			r.log.WarnContext(ctx, "could not close desktop session history", slog.Any("error", err))
		}
	}

	r.log.InfoContext(ctx, "desktop session closed",
		slog.String("session_id", s.ID),
		slog.String("host", s.HostLabel),
		slog.String("reason", reason),
		slog.Int64("bytes_in", in),
		slog.Int64("bytes_out", out))

	r.bus.PublishSessionState(s.UserID, s.ID, string(s.State()), reason)
}

// Get returns a session by id.
func (r *Registry) Get(id string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[id]
	return s, ok
}

// GetForUser returns a session, refusing one that belongs to somebody else.
//
// Reported as not-found rather than forbidden: confirming that a session id exists
// tells an attacker something they should not learn.
func (r *Registry) GetForUser(userID, id string) (*Session, error) {
	s, ok := r.Get(id)
	if !ok || s.UserID != userID {
		return nil, ErrNotFound
	}
	return s, nil
}

// ListForUser returns a user's live desktop sessions.
func (r *Registry) ListForUser(userID string) []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Session, 0, 4)
	for _, s := range r.sessions {
		if s.UserID == userID {
			out = append(out, s)
		}
	}
	return out
}

// Infos returns the serialisable view of a user's desktop sessions.
func (r *Registry) Infos(userID string) []Info {
	sessions := r.ListForUser(userID)
	out := make([]Info, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, s.Info())
	}
	return out
}

func (r *Registry) countForUser(userID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, s := range r.sessions {
		if s.UserID == userID {
			n++
		}
	}
	return n
}

// Count returns the number of live desktop sessions.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// Close terminates a session the user owns.
func (r *Registry) Close(userID, id, reason string) error {
	s, err := r.GetForUser(userID, id)
	if err != nil {
		return err
	}
	s.Close(reason)
	return nil
}

// SweepIdle closes desktops that have had no viewer for longer than the timeout.
//
// The counterweight to backend-owned sessions: without it, closing a browser tab
// leaves a guacd connection and a Windows session allocated indefinitely.
func (r *Registry) SweepIdle() int {
	cutoff := time.Now().Add(-r.cfg.IdleClose)

	r.mu.RLock()
	var stale []*Session
	for _, s := range r.sessions {
		s.mu.Lock()
		idle := s.state == terminal.StateDetached && !s.detachedAt.IsZero() && s.detachedAt.Before(cutoff)
		s.mu.Unlock()
		if idle {
			stale = append(stale, s)
		}
	}
	r.mu.RUnlock()

	for _, s := range stale {
		r.log.Info("closing idle desktop session",
			slog.String("session_id", s.ID),
			slog.String("host", s.HostLabel),
			slog.Duration("idle_for", r.cfg.IdleClose))
		s.Close(fmt.Sprintf("closed after %s with no attached viewer", r.cfg.IdleClose))
	}
	return len(stale)
}

// StartSweeper runs SweepIdle periodically until ctx is cancelled.
func (r *Registry) StartSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.SweepIdle()
		}
	}
}

// CloseAll terminates every desktop session. Called during shutdown.
func (r *Registry) CloseAll(reason string) int {
	r.mu.RLock()
	sessions := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.mu.RUnlock()

	for _, s := range sessions {
		s.Close(reason)
	}
	return len(sessions)
}

// Probe reports whether guacd is reachable, for the readiness endpoint.
//
// ADR 0003 promises /readyz reports guacd reachability and that a missing gateway
// is degraded rather than unavailable -- RDP is one capability, not the product.
func (r *Registry) Probe(ctx context.Context) error {
	if !r.cfg.Enabled() {
		return ErrDisabled
	}
	client, err := Dial(ctx, r.cfg.GuacdAddr)
	if err != nil {
		return err
	}
	// A TCP accept is all this checks. Running a real handshake would need a target
	// host and would count as a connection attempt in guacd's logs every few
	// seconds, which is noise an operator would have to explain.
	return client.Close()
}
