// Package terminal owns live sessions.
//
// The central design decision, from ADR 0004: a session is a backend object and a
// WebSocket is a *view* of it. Attaching or detaching a view does not affect the
// session, so a browser reload, a sleeping laptop, or a dropped VPN does not kill
// a running command.
//
// The safety rule that comes with it: on reattach we replay output and never
// replay input. A keystroke in flight when the socket died is dropped, because
// re-sending it would execute something on the user's behalf after a reconnect --
// exactly what a tool holding root on fifty machines must never do.
package terminal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axt-term/axt-term/backend/internal/sshx"
	"github.com/axt-term/axt-term/backend/internal/store"
)

// State is a session's lifecycle position.
//
// The distinction between Detached and Disconnected is load-bearing in the UI: a
// detached session is alive and will accept input again, while a disconnected one
// is frozen history. Conflating them is how a user comes to believe they restarted
// a service when the keystroke went nowhere.
type State string

const (
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateDetached     State = "detached"
	StateDisconnected State = "disconnected"
	StateFailed       State = "failed"
	StateClosed       State = "closed"
)

// Live reports whether the session can still accept input.
func (s State) Live() bool { return s == StateConnected || s == StateDetached || s == StateConnecting }

// Session is one live terminal.
type Session struct {
	ID        string
	UserID    string
	HostID    string
	HostLabel string
	Protocol  store.Protocol
	RecordID  string // session_records row id
	CreatedAt time.Time
	ClientIP  string

	pty  *sshx.PTY
	conn *sshx.Conn
	ring *RingBuffer

	mu          sync.Mutex
	state       State
	failure     error
	exitReason  string
	attachments map[int64]*attachment
	nextAttach  int64
	detachedAt  time.Time
	recorder    *Recorder

	bytesIn  atomic.Int64 // from the host towards the browser
	bytesOut atomic.Int64 // from the browser towards the host

	closeOnce sync.Once
	done      chan struct{}
	log       *slog.Logger
	onClose   func(*Session)
}

// attachment is one attached viewer.
type attachment struct {
	id   int64
	send chan []byte
	// kicked is closed when the attachment is dropped for falling too far
	// behind, so the WebSocket handler can tell the client why.
	kicked chan struct{}
	once   sync.Once
}

func (a *attachment) close() {
	a.once.Do(func() {
		close(a.send)
	})
}

// attachmentBuffer bounds per-viewer backlog. Terminal output is bursty --
// `find /` produces megabytes in seconds -- and a viewer that cannot keep up must
// be dropped rather than allowed to grow memory or stall the reader.
const attachmentBuffer = 256

// readChunk is the size of each read from the PTY. Large enough that a burst of
// output is a few syscalls rather than thousands, small enough that an
// interactive keystroke echo is not batched behind anything.
const readChunk = 32 * 1024

// State returns the current lifecycle position.
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Failure returns why the session failed, if it did.
func (s *Session) Failure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failure
}

// ExitReason returns a human-readable reason the session ended.
func (s *Session) ExitReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exitReason
}

// Done is closed when the session has ended.
func (s *Session) Done() <-chan struct{} { return s.done }

// Bytes returns the byte counters.
func (s *Session) Bytes() (in, out int64) { return s.bytesIn.Load(), s.bytesOut.Load() }

// Attachments reports how many viewers are attached.
func (s *Session) Attachments() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.attachments)
}

// Size returns the terminal dimensions, which are server-side state and therefore
// survive a reattach.
func (s *Session) Size() (cols, rows int) {
	if s.pty == nil {
		return 0, 0
	}
	return s.pty.Size()
}

// Attachment is what a WebSocket handler receives when it attaches.
type Attachment struct {
	// Replay is the output the client missed, to be written before live data.
	Replay []byte
	// Seq is the absolute offset after Replay, to be sent back on the next
	// attach.
	Seq uint64
	// Gap reports that output was lost, so the client must clear its display
	// rather than append to a partial screen.
	Gap bool
	// Data carries live output. Closed when the attachment ends.
	Data <-chan []byte

	id      int64
	session *Session
}

// Detach ends the attachment. The session keeps running.
func (a *Attachment) Detach() {
	if a == nil || a.session == nil {
		return
	}
	a.session.detach(a.id)
}

// Attach registers a viewer and returns the output it missed.
//
// fromSeq is the absolute offset the client last saw; zero means "send everything
// retained".
func (s *Session) Attach(fromSeq uint64) (*Attachment, error) {
	replay, seq, gap := s.ring.Since(fromSeq)

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.state.Live() {
		return nil, fmt.Errorf("terminal: session is %s", s.state)
	}

	s.nextAttach++
	att := &attachment{
		id:     s.nextAttach,
		send:   make(chan []byte, attachmentBuffer),
		kicked: make(chan struct{}),
	}
	s.attachments[att.id] = att

	if s.state == StateDetached {
		s.state = StateConnected
		s.detachedAt = time.Time{}
	}

	return &Attachment{
		Replay:  replay,
		Seq:     seq,
		Gap:     gap,
		Data:    att.send,
		id:      att.id,
		session: s,
	}, nil
}

func (s *Session) detach(id int64) {
	s.mu.Lock()
	att, ok := s.attachments[id]
	if ok {
		delete(s.attachments, id)
	}
	remaining := len(s.attachments)
	if remaining == 0 && s.state == StateConnected {
		s.state = StateDetached
		s.detachedAt = time.Now()
	}
	s.mu.Unlock()

	if ok {
		att.close()
	}
}

// Write forwards keystrokes to the host.
func (s *Session) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	live := s.state.Live()
	s.mu.Unlock()
	if !live {
		return 0, errors.New("terminal: session is no longer connected")
	}

	n, err := s.pty.Write(p)
	if n > 0 {
		s.bytesOut.Add(int64(n))
		if rec := s.recording(); rec != nil {
			rec.WriteInput(p[:n])
		}
	}
	return n, err
}

// Resize changes the remote window size.
func (s *Session) Resize(cols, rows int) error {
	if s.pty == nil {
		return errors.New("terminal: session has no pseudo-terminal")
	}
	if err := s.pty.Resize(cols, rows); err != nil {
		return err
	}
	if rec := s.recording(); rec != nil {
		rec.WriteResize(cols, rows)
	}
	return nil
}

func (s *Session) recording() *Recorder {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recorder
}

// StartRecording begins writing an asciicast to path.
func (s *Session) StartRecording(path string) error {
	cols, rows := s.Size()
	rec, err := NewRecorder(path, cols, rows, s.HostLabel)
	if err != nil {
		return err
	}
	s.mu.Lock()
	old := s.recorder
	s.recorder = rec
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// StopRecording finishes the current recording, if any.
func (s *Session) StopRecording() error {
	s.mu.Lock()
	rec := s.recorder
	s.recorder = nil
	s.mu.Unlock()
	if rec == nil {
		return nil
	}
	return rec.Close()
}

// IsRecording reports whether output is being written to disk.
func (s *Session) IsRecording() bool { return s.recording() != nil }

// RecordingPath returns the current recording's path, or "".
func (s *Session) RecordingPath() string {
	if rec := s.recording(); rec != nil {
		return rec.Path()
	}
	return ""
}

// pump copies host output into the ring buffer and out to every attachment.
//
// One goroutine per session, owned by the session. It is the only writer to the
// ring buffer, which is why the buffer needs no ordering guarantees beyond its
// own mutex.
func (s *Session) pump() {
	buf := make([]byte, readChunk)
	for {
		n, err := s.pty.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])

			s.bytesIn.Add(int64(n))
			_, _ = s.ring.Write(chunk)
			if rec := s.recording(); rec != nil {
				rec.WriteOutput(chunk)
			}
			s.broadcast(chunk)
		}
		if err != nil {
			s.finish(err)
			return
		}
	}
}

// broadcast delivers a chunk to every attachment, dropping viewers that cannot
// keep up rather than blocking the reader.
func (s *Session) broadcast(chunk []byte) {
	s.mu.Lock()
	var kicked []*attachment
	for id, att := range s.attachments {
		select {
		case att.send <- chunk:
		default:
			// This viewer is more than attachmentBuffer chunks behind. Dropping
			// it is correct: the alternative is stalling the host's output for
			// every other viewer, and the client can reattach and replay.
			kicked = append(kicked, att)
			delete(s.attachments, id)
		}
	}
	if len(s.attachments) == 0 && s.state == StateConnected {
		s.state = StateDetached
		s.detachedAt = time.Now()
	}
	s.mu.Unlock()

	for _, att := range kicked {
		close(att.kicked)
		att.close()
		s.log.Warn("dropped a slow terminal viewer",
			slog.String("session_id", s.ID),
			slog.String("host", s.HostLabel))
	}
}

// finish records why the session ended and tears it down once.
func (s *Session) finish(cause error) {
	s.closeOnce.Do(func() {
		reason := "remote closed the connection"
		state := StateDisconnected

		switch {
		case cause == nil:
		case errors.Is(cause, context.Canceled):
			reason = "closed by user"
			state = StateClosed
		default:
			if code := sshx.ExitCode(cause); code >= 0 {
				reason = fmt.Sprintf("shell exited with status %d", code)
			} else {
				reason = cause.Error()
				state = StateDisconnected
			}
		}

		s.mu.Lock()
		s.state = state
		s.exitReason = reason
		if cause != nil && state == StateFailed {
			s.failure = cause
		}
		atts := make([]*attachment, 0, len(s.attachments))
		for _, a := range s.attachments {
			atts = append(atts, a)
		}
		s.attachments = make(map[int64]*attachment)
		rec := s.recorder
		s.recorder = nil
		s.mu.Unlock()

		for _, a := range atts {
			a.close()
		}
		if rec != nil {
			_ = rec.Close()
		}
		if s.pty != nil {
			_ = s.pty.Close()
		}
		if s.conn != nil {
			s.conn.Release()
		}
		close(s.done)

		if s.onClose != nil {
			s.onClose(s)
		}
	})
}

// Close terminates the session.
func (s *Session) Close(reason string) {
	s.mu.Lock()
	if reason != "" {
		s.exitReason = reason
	}
	s.mu.Unlock()
	s.finish(context.Canceled)
}

// Info is the serialisable view of a session.
type Info struct {
	ID           string         `json:"id"`
	UserID       string         `json:"user_id"`
	HostID       string         `json:"host_id"`
	HostLabel    string         `json:"host_label"`
	Protocol     store.Protocol `json:"protocol"`
	State        State          `json:"state"`
	Cols         int            `json:"cols"`
	Rows         int            `json:"rows"`
	Attachments  int            `json:"attachments"`
	Seq          uint64         `json:"seq"`
	BytesIn      int64          `json:"bytes_in"`
	BytesOut     int64          `json:"bytes_out"`
	Recording    bool           `json:"recording"`
	ExitReason   string         `json:"exit_reason,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	DetachedFor  int64          `json:"detached_for_s,omitempty"`
	SessionRecID string         `json:"session_record_id,omitempty"`
}

// Info returns the serialisable view.
func (s *Session) Info() Info {
	cols, rows := s.Size()

	s.mu.Lock()
	state := s.state
	attachments := len(s.attachments)
	exitReason := s.exitReason
	detachedAt := s.detachedAt
	recording := s.recorder != nil
	s.mu.Unlock()

	var detachedFor int64
	if !detachedAt.IsZero() {
		detachedFor = int64(time.Since(detachedAt).Seconds())
	}

	in, out := s.Bytes()
	return Info{
		ID:           s.ID,
		UserID:       s.UserID,
		HostID:       s.HostID,
		HostLabel:    s.HostLabel,
		Protocol:     s.Protocol,
		State:        state,
		Cols:         cols,
		Rows:         rows,
		Attachments:  attachments,
		Seq:          s.ring.Seq(),
		BytesIn:      in,
		BytesOut:     out,
		Recording:    recording,
		ExitReason:   exitReason,
		CreatedAt:    s.CreatedAt,
		DetachedFor:  detachedFor,
		SessionRecID: s.RecordID,
	}
}
