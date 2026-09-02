package rdp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axt-term/axt-term/backend/internal/store"
	"github.com/axt-term/axt-term/backend/internal/terminal"
)

// State is a desktop session's lifecycle position.
//
// Reused from the terminal package rather than redefined: a detached RDP session
// and a detached SSH session mean the same thing to the person looking at the tab,
// and one vocabulary means the frontend's SessionState type covers both.
type State = terminal.State

// Session errors.
var (
	ErrClosed       = errors.New("rdp: session has ended")
	ErrViewerBusy   = errors.New("rdp: session already has a viewer")
	ErrNoConnection = errors.New("rdp: session has no guacd connection")
)

// instructionQueue bounds how far one viewer may fall behind.
//
// A desktop stream is bursty in the same way terminal output is -- dragging a
// window produces a flood -- and a viewer that cannot keep up has to be dropped
// rather than allowed to grow memory. Larger than the terminal's equivalent
// because a single frame is many instructions.
const instructionQueue = 1024

// maxDroppedStreams bounds the bookkeeping for streams we refused. Without a cap,
// a daemon opening streams in a loop would grow the map forever.
const maxDroppedStreams = 256

// Session is one live remote desktop.
//
// Ownership follows ADR 0004: the session is a backend object and the WebSocket is
// a view of it, so a browser reload does not end the desktop. What differs from a
// PTY is that the instruction stream is *stateful* -- it is a sequence of drawing
// operations, not a byte stream -- so reattaching cannot mean replaying a buffer.
// See Attach for how a returning viewer gets its display back.
type Session struct {
	ID        string
	UserID    string
	HostID    string
	HostLabel string
	Protocol  store.Protocol
	RecordID  string
	CreatedAt time.Time
	ClientIP  string

	guacdAddr string
	// driveEnabled gates file and pipe streams, which are the drive-redirection
	// data path. Captured at create time so a later host edit cannot widen the
	// permissions of a session that is already running.
	driveEnabled bool

	owner *Client

	mu     sync.Mutex
	state  State
	reason string
	// bound is the guacd connection currently feeding the viewer, nil when
	// detached. Which connection that is decides who answers guacd's sync.
	bound      *Client
	viewer     *viewer
	joined     *Client
	everBound  bool
	detachedAt time.Time
	display    Display
	// dropped records stream indices we refused, so their blobs can be suppressed.
	dropped map[string]bool

	bytesIn  atomic.Int64 // guacd towards the browser
	bytesOut atomic.Int64 // browser towards guacd

	closeOnce sync.Once
	done      chan struct{}
	log       *slog.Logger
	onClose   func(*Session)
}

// viewer is one attached WebSocket.
type viewer struct {
	send   chan []byte
	kicked chan struct{}
	once   sync.Once
}

func (v *viewer) close() {
	v.once.Do(func() { close(v.send) })
}

// Info is the serialisable view of a session.
//
// Shaped to match terminal.Info so the frontend's SessionInfo type covers both,
// with pixels where a PTY has columns and rows.
type Info struct {
	ID           string         `json:"id"`
	UserID       string         `json:"user_id"`
	HostID       string         `json:"host_id"`
	HostLabel    string         `json:"host_label"`
	Protocol     store.Protocol `json:"protocol"`
	State        State          `json:"state"`
	Width        int            `json:"width"`
	Height       int            `json:"height"`
	Attachments  int            `json:"attachments"`
	BytesIn      int64          `json:"bytes_in"`
	BytesOut     int64          `json:"bytes_out"`
	ExitReason   string         `json:"exit_reason,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	DetachedFor  int64          `json:"detached_for_s,omitempty"`
	SessionRecID string         `json:"session_record_id,omitempty"`
}

// Info returns the serialisable view.
func (s *Session) Info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()

	attachments := 0
	if s.viewer != nil {
		attachments = 1
	}
	detachedFor := int64(0)
	if s.state == terminal.StateDetached && !s.detachedAt.IsZero() {
		detachedFor = int64(time.Since(s.detachedAt).Seconds())
	}

	return Info{
		ID:           s.ID,
		UserID:       s.UserID,
		HostID:       s.HostID,
		HostLabel:    s.HostLabel,
		Protocol:     s.Protocol,
		State:        s.state,
		Width:        s.display.Width,
		Height:       s.display.Height,
		Attachments:  attachments,
		BytesIn:      s.bytesIn.Load(),
		BytesOut:     s.bytesOut.Load(),
		ExitReason:   s.reason,
		CreatedAt:    s.CreatedAt,
		DetachedFor:  detachedFor,
		SessionRecID: s.RecordID,
	}
}

// State returns the current lifecycle position.
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// ExitReason returns why the session ended.
func (s *Session) ExitReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason
}

// Done is closed when the session has ended.
func (s *Session) Done() <-chan struct{} { return s.done }

// Bytes returns the relay counters.
func (s *Session) Bytes() (in, out int64) { return s.bytesIn.Load(), s.bytesOut.Load() }

// Size returns the current display geometry.
func (s *Session) Size() (width, height int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.display.Width, s.display.Height
}

// Attachment is a viewer's handle on the session.
type Attachment struct {
	// Data carries instructions to send to the browser.
	Data <-chan []byte
	// Kicked is closed when this viewer was displaced or fell too far behind.
	Kicked <-chan struct{}
	// Repainted reports whether this attachment opened a fresh guacd view, which
	// means the browser is receiving a complete display rather than continuing a
	// stream it already had.
	Repainted bool

	session *Session
}

// Detach releases the attachment.
func (a *Attachment) Detach() {
	if a == nil || a.session == nil {
		return
	}
	a.session.detach()
}

// Send forwards one instruction from the browser to guacd.
func (a *Attachment) Send(encoded []byte) error {
	if a == nil || a.session == nil {
		return ErrClosed
	}
	return a.session.send(encoded)
}

// Attach binds a viewer to the session.
//
// The first viewer rides the owner connection directly. A *returning* viewer
// cannot: its canvas is gone and the instructions that painted the old one will
// never be repeated, so this opens a second guacd connection that joins the same
// desktop by id. guacd sends a joining client the current state of the display,
// which is the only way to reconstruct it -- and is guacd's own mechanism, the one
// screen sharing uses, not a workaround.
//
// The cost is honest: while a rejoined viewer is attached, guacd sends the desktop
// stream twice, once to each of our connections. That traffic stays on the
// internal network, and the owner connection has to stay open regardless because
// it is what keeps the desktop alive while nobody is watching.
func (s *Session) Attach(ctx context.Context, display Display) (*Attachment, error) {
	s.mu.Lock()

	if !s.state.Live() {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrClosed, s.reason)
	}
	if s.owner == nil {
		s.mu.Unlock()
		return nil, ErrNoConnection
	}

	// A second viewer displaces the first rather than being refused. Taking over
	// from another tab is the behaviour people expect from a remote desktop, and
	// refusing would leave a session stranded behind a tab they already closed.
	//
	// The displaced viewer's join connection goes with it. Closing it here is what
	// keeps a takeover from orphaning one: its pump would otherwise keep reading the
	// desktop stream and answering guacd's sync for the life of the session, costing
	// a connection and a goroutine on every takeover. Closing a join is safe -- only
	// the owner connection ending finishes the session.
	var displaced *Client
	if s.viewer != nil {
		old := s.viewer
		displaced = s.joined
		s.viewer = nil
		s.bound = nil
		s.joined = nil
		close(old.kicked)
		old.close()
	}

	needsJoin := s.everBound
	s.mu.Unlock()

	if displaced != nil {
		_ = displaced.Close()
	}

	var (
		bound   = s.owner
		join    *Client
		err     error
		painted bool
	)
	if needsJoin {
		join, err = s.openJoin(ctx, display)
		if err != nil {
			// Failing the attach is better than a blank canvas: the client is told
			// to reconnect, which makes a fresh desktop, rather than sitting in
			// front of a pane that will never draw.
			return nil, err
		}
		bound = join
		painted = true
	}

	v := &viewer{send: make(chan []byte, instructionQueue), kicked: make(chan struct{})}

	s.mu.Lock()
	// The session may have ended while the join was in flight.
	if !s.state.Live() {
		s.mu.Unlock()
		if join != nil {
			_ = join.Close()
		}
		return nil, fmt.Errorf("%w: %s", ErrClosed, s.reason)
	}
	s.viewer = v
	s.bound = bound
	s.joined = join
	s.everBound = true
	s.state = terminal.StateConnected
	s.detachedAt = time.Time{}
	if display.Width > 0 && display.Height > 0 {
		s.display = display
	}
	s.mu.Unlock()

	if join != nil {
		go s.pump(join, false)
	}

	return &Attachment{Data: v.send, Kicked: v.kicked, Repainted: painted, session: s}, nil
}

// openJoin dials guacd and joins this session's connection.
func (s *Session) openJoin(ctx context.Context, display Display) (*Client, error) {
	connectionID := s.owner.ConnectionID()

	client, err := Dial(ctx, s.guacdAddr)
	if err != nil {
		return nil, err
	}
	if err := client.Join(ctx, connectionID, display); err != nil {
		_ = client.Close()
		return nil, err
	}
	s.log.Debug("joined desktop session for a returning viewer",
		slog.String("session_id", s.ID),
		slog.String("connection_id", connectionID))
	return client, nil
}

// detach releases the current viewer and closes any join connection.
func (s *Session) detach() {
	s.mu.Lock()
	v := s.viewer
	join := s.joined
	s.viewer = nil
	s.bound = nil
	s.joined = nil
	if s.state.Live() {
		s.state = terminal.StateDetached
		s.detachedAt = time.Now()
	}
	s.mu.Unlock()

	if v != nil {
		v.close()
	}
	// The join connection exists only to serve one viewer; the owner stays.
	if join != nil {
		_ = join.Close()
	}
}

// send forwards a browser instruction to guacd.
func (s *Session) send(encoded []byte) error {
	s.mu.Lock()
	target := s.bound
	live := s.state.Live()
	s.mu.Unlock()

	if !live {
		return ErrClosed
	}
	if target == nil {
		return ErrNoConnection
	}
	s.bytesOut.Add(int64(len(encoded)))
	return target.WriteRaw(encoded)
}

// Resize asks guacd to change the display geometry.
func (s *Session) Resize(width, height int) error {
	s.mu.Lock()
	target := s.bound
	if target == nil {
		target = s.owner
	}
	live := s.state.Live()
	if live && width > 0 && height > 0 {
		s.display.Width = width
		s.display.Height = height
	}
	s.mu.Unlock()

	if !live {
		return ErrClosed
	}
	if target == nil {
		return ErrNoConnection
	}
	return target.Write("size", strconv.Itoa(width), strconv.Itoa(height))
}

// pump reads instructions from a guacd connection and routes them.
//
// isOwner marks the connection that keeps the desktop alive: when it ends, the
// session ends. A join connection ending only means that viewer is gone.
func (s *Session) pump(c *Client, isOwner bool) {
	for {
		in, err := c.Read()
		if err != nil {
			if isOwner {
				s.finish(relayReason(err))
			}
			return
		}

		switch in.Opcode {
		case "sync":
			// Flow control. guacd measures client lag from sync round trips and
			// throttles frames when they go unanswered, so *somebody* must reply.
			// When a viewer is bound, the browser's client does it; when nobody is
			// watching, this goroutine does, which is what stops a detached
			// session's desktop from wedging.
			if !s.forward(c, in) {
				if err := c.Write("sync", in.Arg(0)); err != nil {
					if isOwner {
						s.finish(relayReason(err))
					}
					return
				}
			}

		case "disconnect":
			if isOwner {
				s.finish("guacd closed the connection")
			}
			return

		case "error":
			rerr := remoteErrorFrom(in)
			// Forward first so the browser can show it, then end the session.
			s.forward(c, in)
			if isOwner {
				s.finish(rerr.Error())
			}
			return

		case "file", "pipe":
			// Drive redirection and named pipes are bidirectional data paths into
			// the host, per-host opt-in by ADR 0003. Refusing the stream is not
			// enough: guacd waits for an ack, and its blobs would otherwise arrive
			// with no stream to belong to.
			if !s.driveEnabled {
				s.refuseStream(c, in)
				continue
			}
			s.forward(c, in)

		case "blob", "end":
			if s.isDropped(in.Arg(0)) {
				continue
			}
			s.forward(c, in)

		default:
			s.forward(c, in)
		}
	}
}

// forward sends an instruction to the viewer bound to c, reporting whether it was
// delivered. A viewer bound to a different connection is not this pump's audience.
func (s *Session) forward(c *Client, in Instruction) bool {
	s.mu.Lock()
	if s.bound != c || s.viewer == nil {
		s.mu.Unlock()
		return false
	}
	v := s.viewer
	s.mu.Unlock()

	encoded := in.Encode()
	s.bytesIn.Add(int64(len(encoded)))

	select {
	case v.send <- encoded:
		return true
	default:
		// The viewer is too far behind to catch up. Dropping instructions would
		// corrupt the display silently, which looks like a rendering bug; dropping
		// the viewer is honest and it will reconnect with a full repaint.
		s.log.Warn("dropping desktop viewer that fell behind",
			slog.String("session_id", s.ID),
			slog.String("host", s.HostLabel))
		s.kick(v)
		return true
	}
}

// kick displaces a viewer that cannot keep up.
func (s *Session) kick(v *viewer) {
	s.mu.Lock()
	if s.viewer != v {
		s.mu.Unlock()
		return
	}
	s.viewer = nil
	s.bound = nil
	join := s.joined
	s.joined = nil
	if s.state.Live() {
		s.state = terminal.StateDetached
		s.detachedAt = time.Now()
	}
	s.mu.Unlock()

	close(v.kicked)
	v.close()
	if join != nil {
		_ = join.Close()
	}
}

// refuseStream declines a stream and remembers its index.
func (s *Session) refuseStream(c *Client, in Instruction) {
	index := in.Arg(0)

	s.mu.Lock()
	if s.dropped == nil {
		s.dropped = make(map[string]bool)
	}
	if len(s.dropped) < maxDroppedStreams {
		s.dropped[index] = true
	}
	s.mu.Unlock()

	s.log.Debug("refused a guacd stream",
		slog.String("session_id", s.ID),
		slog.String("opcode", in.Opcode),
		slog.String("reason", "drive redirection is disabled for this host"))

	// Status 256 is "unsupported", which is exactly what this is.
	if err := c.Write("ack", index, "drive redirection is disabled for this host", "256"); err != nil {
		s.log.Debug("could not ack a refused stream", slog.Any("error", err))
	}
}

func (s *Session) isDropped(index string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped[index]
}

// finish records why the session ended and tears it down.
func (s *Session) finish(reason string) {
	s.mu.Lock()
	if s.state.Live() {
		s.state = terminal.StateDisconnected
		if s.reason == "" {
			s.reason = reason
		}
	}
	s.mu.Unlock()
	s.Close(reason)
}

// Close ends the session.
func (s *Session) Close(reason string) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		if s.reason == "" {
			s.reason = reason
		}
		if s.state.Live() {
			s.state = terminal.StateClosed
		}
		v := s.viewer
		join := s.joined
		owner := s.owner
		s.viewer = nil
		s.bound = nil
		s.joined = nil
		s.mu.Unlock()

		if v != nil {
			v.close()
		}
		if join != nil {
			_ = join.Close()
		}
		if owner != nil {
			// Best effort: tell guacd we are going before dropping the socket, so
			// the RDP session on the Windows side is disconnected cleanly rather
			// than left for its idle timer.
			_ = owner.Write("disconnect")
			_ = owner.Close()
		}

		close(s.done)
		if s.onClose != nil {
			s.onClose(s)
		}
	})
}

// relayReason turns a relay failure into something worth showing a person.
func relayReason(err error) string {
	switch {
	case err == nil:
		return "connection ended"
	case errors.Is(err, ErrTooLarge), errors.Is(err, ErrMalformed), errors.Is(err, ErrTooManyArgs):
		// A protocol fault is a guacd or gateway problem, not a user error, and
		// saying so saves somebody checking their password.
		return "the desktop gateway sent an invalid instruction stream: " + err.Error()
	default:
		return "connection to the desktop gateway ended: " + err.Error()
	}
}
