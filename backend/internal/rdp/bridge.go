package rdp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/axt-term/axt-term/backend/internal/auth"
	"github.com/axt-term/axt-term/backend/internal/httpx"
	"github.com/coder/websocket"
)

// WebSocket framing.
//
// The same convention as /ws/terminal: binary frames carry payload behind a
// one-byte opcode, text frames carry JSON control messages. Guacamole
// instructions are themselves text, so relaying them as text frames would have
// been the obvious choice -- but then a control frame and an instruction would be
// indistinguishable without sniffing the content. One convention across both
// sockets is worth more than saving a byte per frame.
const (
	// OpInstruction carries one Guacamole instruction in either direction.
	OpInstruction byte = 0x10
)

// Control message types, carried in text frames.
const (
	CtlStatus = "status"
	CtlError  = "error"
	CtlExit   = "exit"
	CtlResize = "resize"
	CtlPing   = "ping"
	CtlPong   = "pong"
	CtlAck    = "ack"
)

// Control is the JSON shape of every control frame in both directions.
type Control struct {
	Type string `json:"t"`

	// resize
	Width  int `json:"width,omitempty"`
	Height int `json:"height,omitempty"`

	// status
	State string `json:"state,omitempty"`
	Host  string `json:"host,omitempty"`
	// Repainted tells the client it is receiving a complete display rather than
	// the continuation of one, so it can clear whatever it had before drawing.
	Repainted bool `json:"repainted,omitempty"`
	// Protocol lets the client label the session rdp or vnc without another call.
	Protocol string `json:"protocol,omitempty"`

	// error
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`

	// exit
	Reason string `json:"reason,omitempty"`
}

func (c Control) encode() ([]byte, error) { return json.Marshal(c) }

// frame prefixes a payload with an opcode.
func frame(op byte, payload []byte) []byte {
	out := make([]byte, 0, len(payload)+1)
	out = append(out, op)
	out = append(out, payload...)
	return out
}

// WebSocket tuning. Mirrors the terminal bridge, with a larger read limit: a
// clipboard paste or a drive upload blob is bigger than a keystroke.
const (
	readLimit    = 4 << 20
	pingInterval = 30 * time.Second
	pongTimeout  = 10 * time.Second
	writeTimeout = 15 * time.Second

	// attachTimeout bounds the guacd join performed when a viewer returns.
	attachTimeout = 20 * time.Second
)

// Bridge serves /ws/rdp.
type Bridge struct {
	registry       *Registry
	tickets        *auth.TicketStore
	log            *slog.Logger
	allowedOrigins []string
}

// NewBridge creates the WebSocket bridge.
func NewBridge(registry *Registry, tickets *auth.TicketStore, allowedOrigins []string, log *slog.Logger) *Bridge {
	return &Bridge{
		registry:       registry,
		tickets:        tickets,
		log:            log,
		allowedOrigins: allowedOrigins,
	}
}

// acceptOptions builds the upgrade options.
//
// Origin patterns are set explicitly rather than relying on the library default,
// and compression is disabled: the desktop stream is already compressed image
// data, so per-message deflate would burn CPU re-compressing JPEG.
func (b *Bridge) acceptOptions() *websocket.AcceptOptions {
	patterns := make([]string, 0, len(b.allowedOrigins))
	for _, origin := range b.allowedOrigins {
		if host := hostOf(origin); host != "" {
			patterns = append(patterns, host)
		}
	}
	return &websocket.AcceptOptions{
		OriginPatterns:  patterns,
		CompressionMode: websocket.CompressionDisabled,
	}
}

func hostOf(origin string) string {
	if idx := strings.Index(origin, "://"); idx >= 0 {
		return origin[idx+3:]
	}
	return origin
}

// ServeRDP upgrades to a WebSocket and attaches to a desktop session.
//
// Authentication is the single-use ticket, consumed before the upgrade so an
// invalid one produces a clean HTTP error rather than a WebSocket that closes
// immediately for no visible reason.
func (b *Bridge) ServeRDP(w http.ResponseWriter, r *http.Request) {
	ticketValue := r.URL.Query().Get("ticket")
	if ticketValue == "" {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeUnauthenticated,
			"a session ticket is required")
		return
	}

	ticket, err := b.tickets.Consume(ticketValue, httpx.ClientIP(r.Context()), "rdp")
	if err != nil {
		b.log.WarnContext(r.Context(), "rejected desktop websocket",
			slog.Any("error", err),
			slog.String("client_ip", httpx.ClientIP(r.Context())))
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeUnauthenticated,
			"this ticket is not valid; request a new one")
		return
	}

	session, err := b.registry.GetForUser(ticket.UserID, ticket.SessionID)
	if err != nil {
		httpx.NotFound(w, r, "session")
		return
	}

	display := Display{
		Width:  queryInt(r, "width"),
		Height: queryInt(r, "height"),
		DPI:    queryInt(r, "dpi"),
	}

	conn, err := websocket.Accept(w, r, b.acceptOptions())
	if err != nil {
		// Accept has already written a response.
		b.log.WarnContext(r.Context(), "websocket upgrade failed", slog.Any("error", err))
		return
	}
	conn.SetReadLimit(readLimit)

	b.run(r, conn, session, display)
}

func queryInt(r *http.Request, name string) int {
	n, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func (b *Bridge) run(r *http.Request, conn *websocket.Conn, session *Session, display Display) {
	// Deliberately not r.Context(): that is cancelled when the handler returns, and
	// cancellation here is driven by the read loop, the session ending, or the ping
	// loop failing.
	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	defer cancel()

	attachCtx, attachCancel := context.WithTimeout(ctx, attachTimeout)
	attachment, err := session.Attach(attachCtx, display)
	attachCancel()
	if err != nil {
		b.closeWithError(ctx, conn, attachErrorCode(err), err.Error())
		return
	}
	defer attachment.Detach()

	outgoing := make(chan []byte, 64)

	// One writer at a time. A WebSocket message must not be interleaved with
	// another, and there are several senders here: the instruction pump, the kick
	// watcher, the session watcher, and the read loop. writeFrame is the only place
	// that touches the connection, so the serialisation is visible rather than
	// assumed.
	//
	// Control frames are written through it synchronously rather than queued behind
	// the instruction stream: the ones that matter most -- viewer_replaced and exit --
	// are followed immediately by cancel(), and a queued frame would have its write
	// context cancelled before it left.
	var writeMu sync.Mutex
	writeFrame := func(typ websocket.MessageType, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		writeCtx, writeCancel := context.WithTimeout(ctx, writeTimeout)
		defer writeCancel()
		return conn.Write(writeCtx, typ, payload)
	}

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for payload := range outgoing {
			if err := writeFrame(websocket.MessageBinary, payload); err != nil {
				cancel()
				return
			}
		}
	}()

	sendControl := func(c Control) {
		encoded, err := c.encode()
		if err != nil {
			return
		}
		if err := writeFrame(websocket.MessageText, encoded); err != nil {
			cancel()
		}
	}

	width, height := session.Size()
	sendControl(Control{
		Type:      CtlStatus,
		State:     string(session.State()),
		Host:      session.HostLabel,
		Protocol:  string(session.Protocol),
		Width:     width,
		Height:    height,
		Repainted: attachment.Repainted,
	})

	// Forward the desktop stream.
	go func() {
		for {
			select {
			case instruction, ok := <-attachment.Data:
				if !ok {
					cancel()
					return
				}
				select {
				case outgoing <- frame(OpInstruction, instruction):
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// A viewer displaced by another tab, or dropped for falling behind, is told
	// why rather than seeing a socket close for no reason.
	go func() {
		select {
		case <-attachment.Kicked:
			sendControl(Control{
				Type:    CtlError,
				Code:    "viewer_replaced",
				Message: "this desktop was opened in another view",
			})
			cancel()
		case <-ctx.Done():
		}
	}()

	// Detect a session that ends while attached.
	go func() {
		select {
		case <-session.Done():
			sendControl(Control{
				Type:   CtlExit,
				Reason: session.ExitReason(),
				State:  string(session.State()),
			})
			cancel()
		case <-ctx.Done():
		}
	}()

	// Ping loop: TCP will not report a laptop that closed its lid for minutes.
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pingCtx, pingCancel := context.WithTimeout(ctx, pongTimeout)
				err := conn.Ping(pingCtx)
				pingCancel()
				if err != nil {
					b.log.Debug("desktop websocket ping failed",
						slog.String("session_id", session.ID), slog.Any("error", err))
					cancel()
					return
				}
			}
		}
	}()

	readErr := b.readLoop(ctx, conn, session, attachment, sendControl)

	cancel()
	close(outgoing)
	<-writerDone

	status := websocket.StatusNormalClosure
	reason := "closed"
	if readErr != nil && !errors.Is(readErr, context.Canceled) {
		if websocket.CloseStatus(readErr) == -1 {
			status = websocket.StatusInternalError
			reason = "read error"
		}
	}
	_ = conn.Close(status, reason)
}

func (b *Bridge) readLoop(
	ctx context.Context,
	conn *websocket.Conn,
	session *Session,
	attachment *Attachment,
	sendControl func(Control),
) error {
	driveEnabled := session.driveEnabled

	for {
		msgType, payload, err := conn.Read(ctx)
		if err != nil {
			return err
		}

		switch msgType {
		case websocket.MessageBinary:
			if len(payload) == 0 {
				continue
			}
			if payload[0] != OpInstruction {
				sendControl(Control{
					Type:    CtlError,
					Code:    "unknown_opcode",
					Message: "unrecognised binary opcode",
				})
				continue
			}

			in, derr := Decode(payload[1:])
			if derr != nil {
				sendControl(Control{
					Type:    CtlError,
					Code:    "bad_instruction",
					Message: "malformed guacamole instruction",
				})
				continue
			}
			if !AllowedFromClient(in.Opcode, driveEnabled) {
				// Logged at info, not debug: a browser sending a handshake opcode is
				// either a bug worth finding or an attempt worth noticing.
				b.log.InfoContext(ctx, "refused a client instruction",
					slog.String("session_id", session.ID),
					slog.String("opcode", in.Opcode))
				sendControl(Control{
					Type:    CtlError,
					Code:    "opcode_not_permitted",
					Message: "instruction " + in.Opcode + " is not accepted from a client",
				})
				continue
			}
			if in.Opcode == "disconnect" {
				return nil
			}
			if err := attachment.Send(payload[1:]); err != nil {
				sendControl(Control{
					Type:    CtlError,
					Code:    "write_failed",
					Message: err.Error(),
				})
			}

		case websocket.MessageText:
			var c Control
			if err := json.Unmarshal(payload, &c); err != nil {
				sendControl(Control{Type: CtlError, Code: "bad_control", Message: "malformed control frame"})
				continue
			}
			b.handleControl(session, c, sendControl)
		}
	}
}

func (b *Bridge) handleControl(session *Session, c Control, sendControl func(Control)) {
	switch c.Type {
	case CtlResize:
		if err := validateDisplay(c.Width, c.Height); err != nil {
			sendControl(Control{Type: CtlError, Code: "bad_size", Message: err.Error()})
			return
		}
		if err := session.Resize(c.Width, c.Height); err != nil {
			sendControl(Control{Type: CtlError, Code: "resize_failed", Message: err.Error()})
			return
		}
		sendControl(Control{Type: CtlAck, Width: c.Width, Height: c.Height})

	case CtlPing:
		sendControl(Control{Type: CtlPong})

	case CtlPong:
		// Nothing to do; the library handles protocol-level pongs.

	default:
		sendControl(Control{
			Type:    CtlError,
			Code:    "unknown_control",
			Message: "unrecognised control message " + c.Type,
		})
	}
}

// maxDisplayEdge bounds a requested display dimension.
//
// Generous enough for a 4K monitor and its scaling, bounded because width and
// height become a guacd framebuffer allocation.
const maxDisplayEdge = 8192

func validateDisplay(width, height int) error {
	if width < 640 || height < 480 {
		return errors.New("a display smaller than 640x480 is not usable")
	}
	if width > maxDisplayEdge || height > maxDisplayEdge {
		return errors.New("a display larger than 8192 pixels on an edge is not supported")
	}
	return nil
}

// attachErrorCode maps an attach failure onto a code the UI can branch on.
func attachErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrClosed):
		return "session_unavailable"
	case errors.Is(err, ErrUnavailable):
		return "gateway_unavailable"
	case errors.Is(err, ErrRemote), errors.Is(err, ErrHandshake):
		// The join failed. A fresh session is the remedy, and the client is told
		// that rather than being left with a canvas that will never draw.
		return "repaint_failed"
	default:
		return "attach_failed"
	}
}

func (b *Bridge) closeWithError(ctx context.Context, conn *websocket.Conn, code, message string) {
	encoded, err := Control{Type: CtlError, Code: code, Message: message}.encode()
	if err == nil {
		writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
		_ = conn.Write(writeCtx, websocket.MessageText, encoded)
		cancel()
	}
	_ = conn.Close(websocket.StatusPolicyViolation, code)
}
