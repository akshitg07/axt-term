package terminal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/axt-term/axt-term/backend/internal/events"
	"github.com/axt-term/axt-term/backend/internal/sshx"
	"github.com/axt-term/axt-term/backend/internal/store"
	"github.com/google/uuid"
)

// Registry errors.
var (
	ErrNotFound      = errors.New("terminal: session not found")
	ErrSessionLimit  = errors.New("terminal: session limit reached")
	ErrNotPermitted  = errors.New("terminal: session belongs to another user")
	ErrUnsupported   = errors.New("terminal: protocol is not implemented in this build")
	ErrHostNoCommand = errors.New("terminal: host does not support interactive shells")
)

// Config configures the registry.
type Config struct {
	RingBufferSize int
	MaxPerUser     int
	IdleClose      time.Duration
	RecordingsDir  string
	CommandLogging string
	Term           string
}

func (c Config) withDefaults() Config {
	if c.RingBufferSize <= 0 {
		c.RingBufferSize = 256 * 1024
	}
	if c.MaxPerUser <= 0 {
		c.MaxPerUser = 50
	}
	if c.IdleClose <= 0 {
		c.IdleClose = 30 * time.Minute
	}
	if c.Term == "" {
		c.Term = "xterm-256color"
	}
	return c
}

// Registry holds every live session in this process.
type Registry struct {
	cfg   Config
	pool  *sshx.Pool
	store *store.Store
	bus   *events.Bus
	log   *slog.Logger

	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewRegistry creates the registry.
func NewRegistry(cfg Config, pool *sshx.Pool, st *store.Store, bus *events.Bus, log *slog.Logger) *Registry {
	return &Registry{
		cfg:      cfg.withDefaults(),
		pool:     pool,
		store:    st,
		bus:      bus,
		log:      log,
		sessions: make(map[string]*Session),
	}
}

// CreateRequest describes a new session.
type CreateRequest struct {
	UserID   string
	Username string
	Host     *store.Host
	Cols     int
	Rows     int
	ClientIP string
	// Command, when set, runs instead of a login shell. Used by Docker and
	// Kubernetes exec, which reuse this same session machinery.
	Command string
	// Record starts a recording immediately.
	Record bool
}

// Create opens a session to a host.
//
// The SSH dial happens here, synchronously, so a host-key problem or an auth
// failure is reported as the result of the create call rather than arriving later
// over a WebSocket -- which would leave the UI showing a connecting tab with no
// way to explain itself.
func (r *Registry) Create(ctx context.Context, req CreateRequest) (*Session, error) {
	if req.Host == nil {
		return nil, errors.New("terminal: host is required")
	}
	switch req.Host.Protocol {
	case store.ProtocolSSH, store.ProtocolSFTP:
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, req.Host.Protocol)
	}

	if n := r.countForUser(req.UserID); n >= r.cfg.MaxPerUser {
		return nil, fmt.Errorf("%w: %d sessions already open", ErrSessionLimit, n)
	}

	conn, err := r.pool.Acquire(ctx, req.Host.ID)
	if err != nil {
		return nil, err
	}

	pty, err := sshx.OpenPTY(conn.Client(), sshx.PTYConfig{
		Term: r.cfg.Term,
		Cols: req.Cols,
		Rows: req.Rows,
	})
	if err != nil {
		conn.Release()
		return nil, err
	}

	now := time.Now().UTC()
	sess := &Session{
		ID:          uuid.NewString(),
		UserID:      req.UserID,
		HostID:      req.Host.ID,
		HostLabel:   req.Host.Label(),
		Protocol:    store.ProtocolSSH,
		CreatedAt:   now,
		ClientIP:    req.ClientIP,
		pty:         pty,
		conn:        conn,
		ring:        NewRingBuffer(r.cfg.RingBufferSize),
		state:       StateConnected,
		attachments: make(map[int64]*attachment),
		done:        make(chan struct{}),
		log:         r.log,
	}
	sess.onClose = func(s *Session) { r.onSessionClosed(s) }

	// History is recorded before the pump starts so a session that dies
	// immediately still appears in Recent with a reason.
	record := &store.SessionRecord{
		ID:           uuid.NewString(),
		UserID:       req.UserID,
		HostID:       req.Host.ID,
		HostSnapshot: req.Host.Label(),
		Protocol:     store.ProtocolSSH,
		Status:       store.SessionConnected,
		ClientIP:     req.ClientIP,
		StartedAt:    now,
	}
	if err := r.store.CreateSessionRecord(ctx, record); err != nil {
		// Not fatal: losing a history row is worse than nothing, but far better
		// than refusing a connection the engineer needs.
		r.log.WarnContext(ctx, "could not record session history", slog.Any("error", err))
	} else {
		sess.RecordID = record.ID
	}

	if r.shouldRecord(req) {
		path := filepath.Join(r.cfg.RecordingsDir,
			now.Format("2006-01-02"),
			fmt.Sprintf("%s-%s.cast", now.Format("150405"), sess.ID))
		if err := sess.StartRecording(path); err != nil {
			r.log.WarnContext(ctx, "could not start session recording", slog.Any("error", err))
		} else if sess.RecordID != "" {
			if err := r.store.SetSessionRecording(ctx, sess.RecordID, path); err != nil {
				r.log.WarnContext(ctx, "could not store recording path", slog.Any("error", err))
			}
		}
	}

	r.mu.Lock()
	r.sessions[sess.ID] = sess
	r.mu.Unlock()

	go sess.pump()

	r.log.InfoContext(ctx, "session opened",
		slog.String("session_id", sess.ID),
		slog.String("user", req.Username),
		slog.String("host", sess.HostLabel),
		slog.Bool("recording", sess.IsRecording()))

	r.bus.PublishSessionState(req.UserID, sess.ID, string(StateConnected), "")
	return sess, nil
}

// shouldRecord resolves the per-host override against the instance default.
func (r *Registry) shouldRecord(req CreateRequest) bool {
	if req.Record {
		return true
	}
	mode := string(req.Host.CommandLogging)
	if req.Host.CommandLogging == store.LoggingInherit || mode == "" {
		mode = r.cfg.CommandLogging
	}
	return mode == string(store.LoggingFull)
}

func (r *Registry) onSessionClosed(s *Session) {
	r.mu.Lock()
	delete(r.sessions, s.ID)
	r.mu.Unlock()

	in, out := s.Bytes()
	reason := s.ExitReason()

	// A short, independent context: the request that opened the session is long
	// gone, and a cancelled context must not stop history being written.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.RecordID != "" {
		status := store.SessionClosed
		if s.State() == StateFailed {
			status = store.SessionFailed
		} else if s.State() == StateDisconnected {
			status = store.SessionDisconnected
		}
		if err := r.store.CloseSessionRecord(ctx, s.RecordID, status, reason, in, out); err != nil {
			r.log.WarnContext(ctx, "could not close session history", slog.Any("error", err))
		}
	}

	r.log.InfoContext(ctx, "session closed",
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
// Ownership is checked here rather than in each handler so a new endpoint cannot
// forget to do it.
func (r *Registry) GetForUser(userID, id string) (*Session, error) {
	s, ok := r.Get(id)
	if !ok {
		return nil, ErrNotFound
	}
	if s.UserID != userID {
		// Reported as not-found rather than forbidden: confirming that a session
		// id exists tells an attacker something they should not learn.
		return nil, ErrNotFound
	}
	return s, nil
}

// ListForUser returns a user's live sessions.
func (r *Registry) ListForUser(userID string) []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Session, 0, 8)
	for _, s := range r.sessions {
		if s.UserID == userID {
			out = append(out, s)
		}
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

// Close terminates a session the user owns.
func (r *Registry) Close(userID, id, reason string) error {
	s, err := r.GetForUser(userID, id)
	if err != nil {
		return err
	}
	s.Close(reason)
	return nil
}

// Count returns the number of live sessions.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// SweepIdle closes sessions that have had no viewer for longer than the
// configured timeout.
//
// This is the counterweight to backend-owned sessions: without it, a user who
// closes a browser tab leaves a PTY and a ring buffer allocated forever.
func (r *Registry) SweepIdle() int {
	cutoff := time.Now().Add(-r.cfg.IdleClose)

	r.mu.RLock()
	var stale []*Session
	for _, s := range r.sessions {
		s.mu.Lock()
		idle := s.state == StateDetached && !s.detachedAt.IsZero() && s.detachedAt.Before(cutoff)
		s.mu.Unlock()
		if idle {
			stale = append(stale, s)
		}
	}
	r.mu.RUnlock()

	for _, s := range stale {
		r.log.Info("closing idle session",
			slog.String("session_id", s.ID),
			slog.String("host", s.HostLabel),
			slog.Duration("idle_for", r.cfg.IdleClose))
		s.Close(fmt.Sprintf("closed after %s with no attached client", r.cfg.IdleClose))
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

// NotifyShutdown tells every connected client why they are about to be
// disconnected.
//
// http.Server.Shutdown does not track hijacked connections, so without this a
// planned restart looks exactly like a network failure and the browser silently
// retries against a process that is going away.
func (r *Registry) NotifyShutdown(reason string) {
	r.bus.Publish(events.Event{
		Kind: events.KindServerShutdown,
		Data: map[string]any{"reason": reason},
	})
}

// CloseAll terminates every session. Called during shutdown.
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

// Infos returns the serialisable view of a user's sessions.
func (r *Registry) Infos(userID string) []Info {
	sessions := r.ListForUser(userID)
	out := make([]Info, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, s.Info())
	}
	return out
}
